// Package cognito provides authentication strategies using Cognito.
package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
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
	Region       string `json:"region"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	LoginURL     string `json:"loginURL"`
	TokenURL     string `json:"tokenURL"`
}

// Open returns a strategy for logging in through Cognito
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	return &cognitoConnector{
		clientID:      c.ClientID,
		clientSecret:  c.ClientSecret,
		loginURL:      c.LoginURL,
		tokenURL:      c.TokenURL,
		logger:        logger,
		cognitoClient: cognito.New(cognito.Options{Region: c.Region}),
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
	logger        log.Logger
	cognitoClient *cognito.Client
}

func (c *cognitoConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	v := url.Values{}
	v.Set("redirect_uri", callbackURL)
	v.Set("state", state)
	loginUrl, _ := url.Parse(c.loginURL + "?" + v.Encode())
	return loginUrl.String(), nil
}

func (c *cognitoConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	authCode := r.URL.Query().Get("code")
	tokens, err := c.exchangeTokens(authCode)
	if err != nil {
		return identity, fmt.Errorf("cognito: exchange tokens: %v", err)
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

	tokens, err := c.refresh(identity.Username, data.RefreshToken)
	if err != nil {
		return identity, fmt.Errorf("cognito: failed to refresh token: %v", err)
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

func (c *cognitoConnector) authorize(username, password string) (*cognitoTokens, error) {
	authParams := make(map[string]string)
	authParams["USERNAME"] = username
	authParams["PASSWORD"] = password
	authParams["SECRET_HASH"] = c.generateSecretHash(username)

	response, err := c.cognitoClient.InitiateAuth(context.Background(), &cognito.InitiateAuthInput{
		AuthFlow:       "USER_PASSWORD_AUTH",
		ClientId:       &c.clientID,
		AuthParameters: authParams,
	})

	if err != nil {
		return nil, err
	}

	return &cognitoTokens{
		TokenType:    *response.AuthenticationResult.TokenType,
		ExpiresIn:    response.AuthenticationResult.ExpiresIn,
		AccessToken:  *response.AuthenticationResult.AccessToken,
		IdToken:      *response.AuthenticationResult.IdToken,
		RefreshToken: *response.AuthenticationResult.RefreshToken,
	}, nil
}

func (c *cognitoConnector) refresh(username, refreshToken string) (*cognitoTokens, error) {
	authParams := make(map[string]string)
	authParams["REFRESH_TOKEN"] = refreshToken
	authParams["SECRET_HASH"] = c.generateSecretHash(username)

	response, err := c.cognitoClient.InitiateAuth(context.Background(), &cognito.InitiateAuthInput{
		AuthFlow:       "REFRESH_TOKEN_AUTH",
		ClientId:       &c.clientID,
		AuthParameters: authParams,
	})

	if err != nil {
		return nil, err
	}

	return &cognitoTokens{
		TokenType:    *response.AuthenticationResult.TokenType,
		ExpiresIn:    response.AuthenticationResult.ExpiresIn,
		AccessToken:  *response.AuthenticationResult.AccessToken,
		IdToken:      *response.AuthenticationResult.IdToken,
		RefreshToken: refreshToken,
	}, nil
}

func (c *cognitoConnector) generateSecretHash(username string) string {
	h := hmac.New(sha256.New, []byte(c.clientSecret))
	h.Write([]byte(username + c.clientID))
	secretHash := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return secretHash
}

func (c *cognitoConnector) exchangeTokens(authCode string) (*cognitoTokens, error) {
	client := http.DefaultClient

	response, err := client.Get(c.tokenURL + "?code=" + authCode)
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
