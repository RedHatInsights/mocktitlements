package keycloak

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"github.com/redhatinsights/platform-go-middlewares/identity"

	"golang.org/x/oauth2/clientcredentials"
)

// Instance is and instance of the client + host
type Instance struct {
	Client *http.Client
	URL    string
	Log    logr.Logger
}

type UsersSpec struct {
	ID               string              `json:"id"`
	Username         string              `json:"username"`
	Enabled          bool                `json:"enabled"`
	FirstName        string              `json:"firstName"`
	LastName         string              `json:"lastName"`
	Email            string              `json:"email"`
	Attributes       map[string][]string `json:"attributes"`
	CreatedTimestamp int64               `json:"createdTimestamp"`
}

type ClientObject struct {
	ClientID  string `json:"clientId"`
	Name      string `json:"name"`
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	CreatedAt int64  `json:"createdAt"`
}

type attributes struct {
	Oauth2       bool   `json:"oauth2.device.authorization.grant.enabled"`
	GrantEnabled bool   `json:"oidc.ciba.grant.enabled"`
	SamlIdp      string `json:"saml_idp_initiated_sso_url_name"`
}

type clientStruct struct {
	ID                        string         `json:"id"`
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

type credentialsObject struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func createMapper(attr string, mtype string, isMultiValue bool) mapperStruct {
	return mapperStruct{
		Name:           attr,
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-usermodel-attribute-mapper",
		Config: mapperConfig{
			UserInfoTokenClaim: "true",
			UserAttribute:      attr,
			IDTokenClaim:       "true",
			AccessTokenClaim:   "true",
			ClaimName:          attr,
			JSONTypeLabel:      mtype,
			Introspection:      "true",
			Multivalued:        strconv.FormatBool(isMultiValue),
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

func (kc *Instance) CreateClient(clientName, uuid string) error {
	postObj := clientStruct{
		ID:                        uuid,
		DisplayInConsole:          false,
		Name:                      clientName,
		FrontChannelLogout:        true,
		AuthServices:              false,
		ClientID:                  uuid,
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

	url := fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients", kc.URL)
	err := kc.doRequest("POST", url, "create_client", postObj, nil, http.StatusCreated)

	if err != nil {
		return fmt.Errorf("error in client create: %w", err)
	}

	return nil
}

func (kc *Instance) GetClient(clientID string) (ClientObject, error) {
	resp, err := kc.Client.Get(fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/%s", kc.URL, clientID))
	if err != nil {
		kc.Log.Error(err, "could not get client")
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		kc.Log.Error(err, "could not read body data")
	}

	foundClient := ClientObject{}

	err = json.Unmarshal(data, &foundClient)
	if err != nil {
		kc.Log.Error(err, "could not unmarshal clientid")
	}

	kc.Log.Info(fmt.Sprintf("%v", foundClient))

	returnedClient := ClientObject{
		ClientID:  foundClient.ID,
		Name:      foundClient.ClientID,
		CreatedAt: foundClient.CreatedAt,
		Secret:    foundClient.Secret,
	}
	return returnedClient, nil
}

func (kc *Instance) doRequest(method, url, purpose string, postData interface{}, postObject interface{}, expectedStatus int) error {
	var body io.Reader

	if postData != nil {
		b, err := json.Marshal(postData)
		kc.Log.Info(string(b))

		if err != nil {
			return fmt.Errorf("couldn't marshal post object for %s: %w", purpose, err)
		}

		body = strings.NewReader(string(b))
	}

	kc.Log.Info(url)

	req, err := http.NewRequest(method, url, body)

	if err != nil {
		return fmt.Errorf("couldn't create %s request: %w", purpose, err)
	}

	req.Header.Add("Content-Type", "application/json")
	resp, err := kc.Client.Do(req)

	if err != nil {
		return fmt.Errorf("couldn't do %s post: %w", purpose, err)
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("could not read %s body data: %w", purpose, err)
	}

	if postObject != nil {
		err = json.Unmarshal(data, postObject)

		if err != nil {
			kc.Log.Error(err, "could not unmarshal data")
			kc.Log.Info(fmt.Sprintf("%v", data))
			return fmt.Errorf("could not unmarshal %s data: %w", purpose, err)
		}
	}

	if expectedStatus != 0 && resp.StatusCode != expectedStatus {
		return fmt.Errorf("create failed: %s", string(data))
	}

	return nil
}

func (kc *Instance) CreateMapper(id, attributeName, attributeType string, isMultiValue bool) error {
	mapperObj := createMapper(attributeName, attributeType, isMultiValue)
	url := fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/%s/protocol-mappers/models", kc.URL, id)

	err := kc.doRequest("POST", url, "mapper", mapperObj, nil, http.StatusCreated)

	if err != nil {
		return fmt.Errorf("error in mapper create: %w", err)
	}

	return nil
}

func (kc *Instance) GetServiceAccountQuery(queryString string, queryParams url.Values) ([]UsersSpec, error) {
	kcURL, err := url.Parse(kc.URL)
	if err != nil {
		return []UsersSpec{}, fmt.Errorf("couldn't parse keycloak url: %w", err)
	}

	query := url.Values{}
	query.Set("enabled", "true")

	for k, v := range queryParams {
		for _, val := range v {
			query.Add(k, val)
		}
	}

	if queryString != "" {
		query.Set("q", queryString)
	}

	murl := url.URL{
		Scheme:   kcURL.Scheme,
		Host:     kcURL.Host,
		Path:     "auth/admin/realms/redhat-external/users",
		RawQuery: query.Encode(),
	}

	obj := &[]UsersSpec{}
	err = kc.doRequest("GET", murl.String(), "sa_query", nil, obj, http.StatusOK)

	if err != nil {
		return []UsersSpec{}, fmt.Errorf("could not do service account query: %w", err)
	}

	return *obj, nil
}

func (kc *Instance) GetServiceUser(clientID string) (*UsersSpec, error) {
	obj := &UsersSpec{}
	url := fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/%s/service-account-user", kc.URL, clientID)
	err := kc.doRequest("GET", url, "sa_user", nil, obj, http.StatusOK)

	if err != nil {
		return &UsersSpec{}, nil
	}

	return obj, nil
}

func (kc *Instance) GetKeycloakUser(clientID string) (*UsersSpec, error) {
	obj := &UsersSpec{}
	url := fmt.Sprintf("%s/auth/admin/realms/redhat-external/users/%s", kc.URL, clientID)
	err := kc.doRequest("GET", url, "kc_user", nil, obj, http.StatusOK)

	if err != nil {
		return &UsersSpec{}, nil
	}

	return obj, nil
}

type AttributesRequest struct {
	Attributes map[string][]string `json:"attributes"`
}

func (kc *Instance) AddServiceUserAttributes(attrs map[string][]string, id string) error {

	kcURL, err := url.Parse(kc.URL)
	if err != nil {
		return fmt.Errorf("couldn't parse keycloak url: %w", err)
	}

	murl := url.URL{
		Scheme: kcURL.Scheme,
		Host:   kcURL.Host,
		Path:   fmt.Sprintf("auth/admin/realms/redhat-external/users/%s", id),
	}

	attributes := AttributesRequest{
		Attributes: attrs,
	}

	err = kc.doRequest("PUT", murl.String(), "attrs", attributes, nil, http.StatusNoContent)

	if err != nil {
		return fmt.Errorf("couldn't do request: %w", err)
	}

	return nil
}

func (kc *Instance) GetClientSecret(clientID string) (string, error) {
	url := fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/%s/client-secret", kc.URL, clientID)
	obj := &credentialsObject{}
	err := kc.doRequest("GET", url, "client_secret", nil, obj, http.StatusOK)

	if err != nil {
		return "", fmt.Errorf("could not get client secret %w: ", err)
	}

	return obj.Value, nil
}

func (kc *Instance) getUserFromIdentity(r *http.Request) (*User, error) {
	b64Identity := r.Header.Get("x-rh-identity")
	if b64Identity == "" {
		return &User{}, fmt.Errorf("no x-rh-identity header")
	}

	decodedIdentity, err := base64.StdEncoding.DecodeString(b64Identity)
	if err != nil {
		return &User{}, err
	}

	identity := &identity.XRHID{}
	err = json.Unmarshal(decodedIdentity, &identity)
	if err != nil {
		return &User{}, err
	}

	if identity.Identity.Type != "User" || identity.Identity.User.Username == "" {
		return &User{}, fmt.Errorf("x-rh-identity does not contain username ok")
	}

	user, err := kc.FindUserByID(identity.Identity.User.Username)
	if err != nil {
		return &User{}, err
	}

	return user, nil
}

type User struct {
	Username      string   `json:"username"`
	ID            int      `json:"id"`
	Email         string   `json:"email"`
	FirstName     string   `json:"first_name"`
	LastName      string   `json:"last_name"`
	AccountNumber string   `json:"account_number"`
	AddressString string   `json:"address_string"`
	IsActive      bool     `json:"is_active"`
	IsOrgAdmin    bool     `json:"is_org_admin"`
	IsInternal    bool     `json:"is_internal"`
	Locale        string   `json:"locale"`
	OrgID         int      `json:"org_id"`
	DisplayName   string   `json:"display_name"`
	Type          string   `json:"type"`
	Entitlements  []string `json:"entitlements"`
}

func (kc *Instance) FindUserByID(username string) (*User, error) {
	users, err := kc.getUsers()

	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.Username == username {
			return &user, nil
		}
	}
	return nil, fmt.Errorf("User is not known")
}

func (kc *Instance) GetUser(_ http.ResponseWriter, r *http.Request) (*User, error) {
	userObj, err := kc.getUserFromIdentity(r)

	if err != nil {
		return &User{}, fmt.Errorf("couldn't find user: %s", err.Error())
	}
	return userObj, nil
}

func (kc *Instance) getUsers() ([]User, error) {
	obj := &[]UsersSpec{}
	url := kc.URL + "/auth/admin/realms/redhat-external/users?max=2000"
	err := kc.doRequest("GET", url, "get users", nil, obj, http.StatusOK)
	if err != nil {
		return []User{}, fmt.Errorf("could not get users: %w", err)
	}

	return ParseUsers(kc.Log, obj)
}

func ParseUsers(log logr.Logger, obj *[]UsersSpec) ([]User, error) {
	users := []User{}

	for _, user := range *obj {
		attributesToCheck := []string{"is_active", "is_org_admin", "is_internal", "account_id", "org_id", "entitlements", "account_number"}
		valid := true
		for _, attr := range attributesToCheck {
			if len(user.Attributes[attr]) == 0 {
				valid = false
				log.Info(fmt.Sprintf("User %s does not have field [%s]", user.Username, attr))
				continue
			}
		}

		if !valid {
			log.Info(fmt.Sprintf("Skipping user %s as attributes are missing", user.Username))
			continue
		}

		IsActiveRaw := user.Attributes["is_active"][0]
		IsActive, _ := strconv.ParseBool(IsActiveRaw)

		IsOrgAdminRaw := user.Attributes["is_org_admin"][0]
		IsOrgAdmin, _ := strconv.ParseBool(IsOrgAdminRaw)

		IsInternalRaw := user.Attributes["is_internal"][0]
		IsInternal, _ := strconv.ParseBool(IsInternalRaw)

		IDRaw := user.Attributes["account_id"][0]
		ID, _ := strconv.Atoi(IDRaw)

		OrgIDRaw := user.Attributes["org_id"][0]
		OrgID, _ := strconv.Atoi(OrgIDRaw)

		users = append(users, User{
			Username:      user.Username,
			ID:            ID,
			Email:         user.Email,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			AccountNumber: user.Attributes["account_number"][0],
			AddressString: "unknown",
			IsActive:      IsActive,
			IsOrgAdmin:    IsOrgAdmin,
			IsInternal:    IsInternal,
			Locale:        "en_US",
			OrgID:         OrgID,
			DisplayName:   user.FirstName,
			Type:          "User",
			Entitlements:  user.Attributes["newEntitlements"],
		})
	}

	return users, nil
}
