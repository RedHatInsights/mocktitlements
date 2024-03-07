package keycloak

import (
	"context"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/oauth2/clientcredentials"
)

// Instance is and instance of the client + host
type Instance struct {
	Client *http.Client
	URL    string
}

type UsersSpec struct {
	Username   string              `json:"username"`
	Enabled    bool                `json:"enabled"`
	FirstName  string              `json:"firstName"`
	LastName   string              `json:"lastName"`
	Email      string              `json:"email"`
	Attributes map[string][]string `json:"attributes"`
}

type ClientObject struct {
	ClientID string `json:"clientId"`
	Name     string `json:"name"`
	ID       string `json:"id"`
}

// GetKeycloakInstance returns an instance of the keycloak instance with client + host
func GetKeycloakInstance() *Instance {
	keyCloakServer := os.Getenv("KEYCLOAK_SERVER")
	keyCloakUsername := os.Getenv("KEYCLOAK_USERNAME")
	keyCloakPassword := os.Getenv("KEYCLOAK_PASSWORD")
	if keyCloakUsername == "" {
		keyCloakUsername = "admin"
	}
	if keyCloakPassword == "" {
		keyCloakPassword = "admin"
	}

	oauthClientConfig := clientcredentials.Config{
		ClientID:       "admin-cli",
		ClientSecret:   "",
		TokenURL:       keyCloakServer + "/auth/realms/master/protocol/openid-connect/token",
		EndpointParams: url.Values{"grant_type": {"password"}, "username": {keyCloakUsername}, "password": {keyCloakPassword}},
	}

	k := oauthClientConfig.Client(context.Background())
	kc := &Instance{
		Client: k,
		URL:    keyCloakServer,
	}
	return kc
}
