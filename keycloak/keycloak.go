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

func (kc *Instance) CreateClient(clientName, uuid, orgID string) error {
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

func (kc *Instance) CreateMapper(id, attributeName, attributeType string, isMultiValue bool) error {
	mapperObj := createMapper(attributeName, attributeType, isMultiValue)

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

func (kc *Instance) GetServiceUser(clientID string) (*UsersSpec, error) {
	resp, err := kc.Client.Get(fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/%s/service-account-user", kc.URL, clientID))
	if err != nil {
		kc.Log.Error(err, "could not get service account user")
		return &UsersSpec{}, fmt.Errorf("couldn't get service account user: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return &UsersSpec{}, fmt.Errorf("couldn't read body data: %w", err)
	}

	obj := &UsersSpec{}
	err = json.Unmarshal(data, obj)
	if err != nil {
		return &UsersSpec{}, fmt.Errorf("couldn't unmarshal data: %w", err)
	}
	return obj, nil
}

func (kc *Instance) GetKeycloakUser(clientID string) (*UsersSpec, error) {
	resp, err := kc.Client.Get(fmt.Sprintf("%s/auth/admin/realms/redhat-external/users/%s", kc.URL, clientID))
	if err != nil {
		kc.Log.Error(err, "could not get service account user")
		return &UsersSpec{}, fmt.Errorf("couldn't get service account user: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return &UsersSpec{}, fmt.Errorf("couldn't read body data: %w", err)
	}

	obj := &UsersSpec{}
	err = json.Unmarshal(data, obj)
	if err != nil {
		return &UsersSpec{}, fmt.Errorf("couldn't unmarshal body data: %w", err)
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

	requestBytes, err := json.Marshal(attributes)
	if err != nil {
		return fmt.Errorf("couldn't create attributes request: %w", err)
	}

	re := strings.NewReader(string(requestBytes))

	req, err := http.NewRequest("PUT", murl.String(), re)
	if err != nil {
		return fmt.Errorf("couldn't create request: %w", err)
	}

	kc.Log.Info(fmt.Sprintf("%v", req))
	resp, err := kc.Client.Do(req)

	if err != nil {
		return fmt.Errorf("couldn't do request: %w", err)
	}

	kc.Log.Info(fmt.Sprintf("%v", resp))
	defer resp.Body.Close()

	return nil
}

func (kc *Instance) GetClientSecret(clientID string) (string, error) {
	resp, err := kc.Client.Get(fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/%s/client-secret", kc.URL, clientID))
	if err != nil {
		return "", fmt.Errorf("couldn't do request: %w", err)
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("couldn't read body data: %w", err)
	}

	obj := &credentialsObject{}
	err = json.Unmarshal(data, obj)
	if err != nil {
		return "", fmt.Errorf("couldn't unmarshal body data: %w", err)
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

func (kc *Instance) getUsers() (users []User, err error) {
	resp, err := kc.Client.Get(kc.URL + "/auth/admin/realms/redhat-external/users?max=2000")
	if err != nil {
		fmt.Printf("\n\n%s\n\n", err.Error())
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return ParseUsers(kc.Log, data)
}

func ParseUsers(log logr.Logger, data []byte) ([]User, error) {
	obj := &[]UsersSpec{}

	err := json.Unmarshal(data, obj)

	if err != nil {
		return nil, err
	}

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
