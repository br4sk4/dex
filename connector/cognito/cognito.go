// Package cognito_connector provides authentication strategies using Cognito.
package cognito

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/cristalhq/jwt/v4"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"io"
	"math/big"
	"net/http"
	"net/url"
)

var (
	_ connector.CallbackConnector = (*cognitoConnector)(nil)
	_ connector.RefreshConnector  = (*cognitoConnector)(nil)
)

type Config struct {
	LoginURL string `json:"loginURL"`
	TokenURL string `json:"tokenURL"`
}

// Open returns a strategy for logging in through Cognito
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	return &cognitoConnector{
		loginURL:   c.LoginURL,
		tokenURL:   c.TokenURL,
		pathSuffix: "/" + id,
		logger:     logger,
	}, nil
}

type connectorData struct {
	RefreshToken string `json:"refreshToken"`
}

type cognitoConnector struct {
	clientID      string
	clientSecret  string
	loginURL      string
	tokenURL      string
	pathSuffix    string
	logger        log.Logger
	cognitoClient *cognito.Client
}

func (c *cognitoConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	u.Path += c.pathSuffix
	v := url.Values{}
	v.Set("redirect_uri", u.String())
	v.Set("state", state)
	loginUrl, _ := url.Parse(c.loginURL + "?" + v.Encode())
	return loginUrl.String(), nil
}

func (c *cognitoConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	authCode := r.URL.Query().Get("code")
	tokens, err := c.exchangeTokens(authCode)
	if err != nil {
		return identity, fmt.Errorf("cognito: failed to exchange tokens: %v", err)
	}

	idToken, err := parseToken(tokens.IdToken)
	if err != nil {
		return identity, fmt.Errorf("cognito: failed to parse token: %v", err)
	}

	var claims cognitoClaims
	err = json.Unmarshal(idToken.Claims(), &claims)
	if err != nil {
		return identity, fmt.Errorf("cognito: failed to unmarshal token claims: %v", err)
	}

	identity = connector.Identity{
		UserID:        claims.UserID,
		Username:      claims.Username,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Groups:        claims.Groups,
	}

	if s.OfflineAccess {
		data := connectorData{
			RefreshToken: tokens.RefreshToken,
		}
		connData, err := json.Marshal(data)
		if err != nil {
			return identity, fmt.Errorf("cognito: failed to marshal connector data: %v", err)
		}
		identity.ConnectorData = connData
	}

	return identity, nil
}

func (c *cognitoConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	var data connectorData
	if err := json.Unmarshal(identity.ConnectorData, &data); err != nil {
		return identity, fmt.Errorf("cognito: failed to unmarshal connector data: %v", err)
	}

	tokens, err := c.refreshTokens(identity.Username, data.RefreshToken)
	if err != nil {
		return identity, fmt.Errorf("cognito: failed to refresh tokens: %v", err)
	}

	idToken, err := parseToken(tokens.IdToken)
	if err != nil {
		return identity, fmt.Errorf("cognito: failed to parse token: %v", err)
	}

	var claims cognitoClaims
	err = json.Unmarshal(idToken.Claims(), &claims)
	if err != nil {
		return identity, fmt.Errorf("cognito: failed to unmarshal token claims: %v", err)
	}

	identity.UserID = claims.UserID
	identity.Username = claims.Username
	identity.Email = claims.Email
	identity.EmailVerified = claims.EmailVerified
	identity.Groups = claims.Groups

	return identity, nil
}

func (c *cognitoConnector) exchangeTokens(authCode string) (*cognitoTokens, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	tokenRequestBody, err := json.Marshal(&tokenRequest{
		GrantType: "authorization_code",
		Code:      authCode,
	})
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, c.tokenURL, bytes.NewBuffer(tokenRequestBody))
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	var tokens cognitoTokens
	if err := json.Unmarshal(responseBody, &tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

func (c *cognitoConnector) refreshTokens(username, refreshToken string) (*cognitoTokens, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	tokenRequestBody, err := json.Marshal(&tokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
		Username:     username,
	})
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, c.tokenURL, bytes.NewBuffer(tokenRequestBody))
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	var tokens cognitoTokens
	if err := json.Unmarshal(responseBody, &tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

type cognitoKey struct {
	Keys []struct {
		KeyType   string `json:"kty"`
		KeyID     string `json:"kid"`
		Algorythm string `json:"alg"`
		E         string `json:"e"`
		N         string `json:"n"`
		Usage     string `json:"use"`
	} `json:"keys"`
}

type cognitoTokens struct {
	TokenType    string
	ExpiresIn    int32
	AccessToken  string
	IdToken      string
	RefreshToken string
}

type cognitoClaims struct {
	UserID        string   `json:"sub"`
	Username      string   `json:"cognito:username"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"cognito:groups"`
}

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Username     string `json:"username,omitempty"`
}

func parseToken(token string) (*jwt.Token, error) {
	parsedToken, parseError := jwt.ParseNoVerify([]byte(token))
	if parseError != nil {
		return nil, parseError
	}

	var claims jwt.RegisteredClaims
	if unmarshalError := json.Unmarshal(parsedToken.Claims(), &claims); unmarshalError != nil {
		return nil, unmarshalError
	}

	response, httpError := http.DefaultClient.Get(claims.Issuer + "/.well-known/jwks.json")
	if httpError != nil {
		return nil, httpError
	}

	body, httpError := io.ReadAll(response.Body)
	if httpError != nil {
		return nil, httpError
	}

	var jwk cognitoKey
	if unmarshalError := json.Unmarshal(body, &jwk); unmarshalError != nil {
		return nil, unmarshalError
	}

	keyMap := make(map[string]*rsa.PublicKey, 0)

	for i, v := range jwk.Keys {
		publicKey := convertKey(v.E, v.N)
		keyMap[jwk.Keys[i].KeyID] = publicKey
	}

	verifier, verificationError := jwt.NewVerifierRS(jwt.RS256, keyMap[parsedToken.Header().KeyID])
	if verificationError != nil {
		return nil, verificationError
	}

	verifiedToken, verificationError := jwt.Parse([]byte(token), verifier)
	if verificationError != nil {
		return nil, verificationError
	}

	return verifiedToken, nil
}

func convertKey(rawE, rawN string) *rsa.PublicKey {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		panic(err)
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		panic(err)
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey
}
