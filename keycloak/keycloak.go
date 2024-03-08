package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/go-logr/logr"

	"golang.org/x/oauth2/clientcredentials"
)

// Instance is and instance of the client + host
type Instance struct {
	Client *http.Client
	URL    string
	Log    logr.Logger
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

type attributes struct {
	Oauth2       bool   `json:"oauth2.device.authorization.grant.enabled"`
	GrantEnabled bool   `json:"oidc.ciba.grant.enabled"`
	SamlIdp      string `json:"saml_idp_initiated_sso_url_name"`
}

type clientStruct struct {
	ClientID                  string         `json:"clientId"`
	Name                      string         `json:"name"`
	BearerOnly                bool           `json:"bearerOnly,omitempty"`
	PublicClient              bool           `json:"publicClient"`
	BaseURL                   string         `json:"baseUrl"`
	ProtocolMappers           []mapperStruct `json:"protocolMappers"`
	DirectAccessGrantsEnabled bool           `json:"directAccessGrantsEnabled"`
	Attributes                attributes     `json:"attributes"`
	StandardFlow              bool           `json:"standardFlowEnabled"`
	ImplicitFlow              bool           `json:"implicitFlowEnabled"`
	Protocol                  string         `json:"protocol"`
	ServiceAccounts           bool           `json:"serviceAccountsEnabled"`
	Description               string         `json:"description"`
	AuthServices              bool           `json:"authorizationServicesEnabled"`
	FrontChannelLogout        bool           `json:"frontchannelLogout"`
	RootURL                   string         `json:"rootUrl"`
	DisplayInConsole          bool           `json:"alwaysDisplayInConsole"`
}

type mapperConfig struct {
	UserInfoTokenClaim string `json:"userinfo.token.claim"`
	UserAttribute      string `json:"user.attribute"`
	IDTokenClaim       string `json:"id.token.claim"`
	AccessTokenClaim   string `json:"access.token.claim"`
	ClaimName          string `json:"claim.name"`
	JSONTypeLabel      string `json:"jsonType.label"`
	Multivalued        string `json:"multivalued"`
	Introspection      string `json:"introspection.token.claim"`
}

type mapperStruct struct {
	Name           string       `json:"name"`
	Protocol       string       `json:"protocol"`
	ProtocolMapper string       `json:"protocolMapper"`
	Config         mapperConfig `json:"config"`
}

func createMapper(attr string, mtype string) mapperStruct {
	return mapperStruct{
		Name:           attr,
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-usermodel-attribute-mapper",
		Config: mapperConfig{
			UserInfoTokenClaim: "true",
			UserAttribute:      "",
			IDTokenClaim:       "true",
			AccessTokenClaim:   "true",
			ClaimName:          "",
			JSONTypeLabel:      mtype,
			Introspection:      "true",
		},
	}
}

// GetKeycloakInstance returns an instance of the keycloak instance with client + host
func GetKeycloakInstance(log logr.Logger) *Instance {
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
		Log:    log,
	}
	return kc
}

func (kc *Instance) CreateClient(clientName, orgID string) error {
	postObj := clientStruct{
		DisplayInConsole:          false,
		Name:                      "",
		FrontChannelLogout:        true,
		AuthServices:              false,
		ClientID:                  clientName,
		PublicClient:              false,
		DirectAccessGrantsEnabled: false,
		StandardFlow:              false,
		ImplicitFlow:              false,
		Protocol:                  "openid-connect",
		ServiceAccounts:           true,
		Attributes: attributes{
			Oauth2:       false,
			GrantEnabled: false,
			SamlIdp:      "",
		},
	}

	b, err := json.Marshal(postObj)
	kc.Log.Info(string(b))

	// This will go later - just to make linter happy
	kc.Log.Info(orgID)

	if err != nil {
		return fmt.Errorf("couldn't marshal post object: %w", err)
	}

	body := strings.NewReader(string(b))
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients", kc.URL), body)

	if err != nil {
		return fmt.Errorf("couldn't create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	resp, err := kc.Client.Do(req)

	if err != nil {
		return fmt.Errorf("couldn't do post: %w", err)
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("could not read body data: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create failed" + string(data))
	}
	return nil
}

func (kc *Instance) GetClient(clientName string) (ClientObject, error) {
	resp, err := kc.Client.Get(fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients", kc.URL))
	if err != nil {
		kc.Log.Error(err, "could not get client")
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		kc.Log.Error(err, "could not read body data")
	}

	clientList := []ClientObject{}

	err = json.Unmarshal(data, &clientList)
	if err != nil {
		kc.Log.Error(err, "could not unmarshal clientid")
	}

	var foundClient ClientObject
	for _, kclient := range clientList {
		if kclient.ClientID == clientName {
			foundClient = kclient
			break
		}
	}
	kc.Log.Info(fmt.Sprintf("%v", foundClient))
	return foundClient, nil
}

func (kc *Instance) CreateMapper(id string) error {
	mapperObj := createMapper("org_id", "String")

	b, err := json.Marshal(mapperObj)
	kc.Log.Info(string(b))

	if err != nil {
		return fmt.Errorf("couldn't marshal post object for mapper: %w", err)
	}

	kc.Log.Info(fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/%s/protocol-mappers/models", kc.URL, id))

	body := strings.NewReader(string(b))
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/%s/protocol-mappers/models", kc.URL, id), body)

	if err != nil {
		return fmt.Errorf("couldn't create mapper request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	resp, err := kc.Client.Do(req)

	if err != nil {
		return fmt.Errorf("couldn't do mapper post: %w", err)
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("could not read mapper body data: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create failed" + string(data))
	}
	return nil
}

func (kc *Instance) GetServiceAccountQuery(queryString string) ([]UsersSpec, error) {
	kcURL, err := url.Parse(kc.URL)
	if err != nil {
		return []UsersSpec{}, fmt.Errorf("couldn't parse keycloak url: %w", err)
	}

	query := url.Values{}
	query.Set("enabled", "true")
	query.Set("first", "0")
	query.Set("max", "51")

	if queryString != "" {
		query.Set("q", queryString)
	}

	murl := url.URL{
		Scheme:   kcURL.Scheme,
		Host:     kcURL.Host,
		Path:     "auth/admin/realms/redhat-external/users",
		RawQuery: query.Encode(),
	}
	re := strings.NewReader("")

	req, err := http.NewRequest("GET", murl.String(), re)
	if err != nil {
		return []UsersSpec{}, fmt.Errorf("couldn't create request: %w", err)
	}

	kc.Log.Info(fmt.Sprintf("%v", req))
	resp, err := kc.Client.Do(req)

	if err != nil {
		return []UsersSpec{}, fmt.Errorf("couldn't do request: %w", err)
	}

	kc.Log.Info(fmt.Sprintf("%v", resp))
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return []UsersSpec{}, fmt.Errorf("couldn't read body data: %w", err)
	}

	obj := &[]UsersSpec{}
	err = json.Unmarshal(data, obj)

	if err != nil {
		kc.Log.Error(err, "could not unmarshal data")
		kc.Log.Info(fmt.Sprintf("%v", data))
	}

	return *obj, nil
}
