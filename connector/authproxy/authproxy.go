// Package authproxy implements a connector which relies on external
// authentication (e.g. mod_auth in Apache2) and returns an identity with the
// HTTP header X-Remote-User as verified email.
package authproxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds the configuration parameters for a connector which returns an
// identity with the HTTP header X-Remote-User as verified email,
// X-Remote-Group and configured staticGroups as user's group.
// Headers retrieved to fetch user's email and group can be configured
// with userHeader and groupHeader.
type Config struct {
	UserHeader  string   `json:"userHeader"`
	GroupHeader string   `json:"groupHeader"`
	EmailHeader string   `json:"emailHeader"`
	Groups      []string `json:"staticGroups"`
}

// Open returns an authentication strategy which requires no user interaction.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	userHeader := c.UserHeader
	if userHeader == "" {
		userHeader = "X-Remote-User"
	}
	emailHeader := c.EmailHeader
	if emailHeader == "" {
		emailHeader = "X-Remote-Email"
	}
	groupHeader := c.GroupHeader
	if groupHeader == "" {
		groupHeader = "X-Remote-Group"
	}

	return &authproxyConnector{userHeader: userHeader, emailHeader: emailHeader, groupHeader: groupHeader, logger: logger, pathSuffix: "/" + id, groups: c.Groups}, nil
}

// Callback is a connector which returns an identity with the HTTP header
// X-Remote-User as verified email.
type authproxyConnector struct {
	userHeader  string
	emailHeader string
	groupHeader string
	groups      []string
	logger      log.Logger
	pathSuffix  string
}

var identity connector.Identity

var (
	_ connector.CallbackConnector = (*authproxyConnector)(nil)
	_ connector.RefreshConnector  = (*authproxyConnector)(nil)
)

// LoginURL returns the URL to redirect the user to login with.
func (m *authproxyConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	u.Path += m.pathSuffix
	v := u.Query()
	v.Set("state", state)
	u.RawQuery = v.Encode()
	return u.String(), nil
}

// HandleCallback parses the request and returns the user's identity
func (m *authproxyConnector) HandleCallback(s connector.Scopes, r *http.Request) (connector.Identity, error) {
	remoteUser := r.Header.Get(m.userHeader)
	if remoteUser == "" {
		return connector.Identity{}, fmt.Errorf("required HTTP header %s is not set", m.userHeader)
	}
	remoteEmail := r.Header.Get(m.emailHeader)
	if remoteEmail == "" {
		return connector.Identity{}, fmt.Errorf("required HTTP header %s is not set", m.userHeader)
	}
	groups := m.groups
	headerGroup := r.Header.Get(m.groupHeader)
	if headerGroup != "" {
		splitheaderGroup := strings.Split(headerGroup, ",")
		for i, v := range splitheaderGroup {
			splitheaderGroup[i] = strings.TrimSpace(v)
		}
		groups = append(splitheaderGroup, groups...)
	}

	identity = connector.Identity{
		UserID:        remoteUser, // TODO: figure out if this is a bad ID value.
		Username:      remoteUser,
		Email:         remoteEmail,
		EmailVerified: true,
		Groups:        groups,
	}
	return identity, nil
}

func (m *authproxyConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	return identity, nil
}
