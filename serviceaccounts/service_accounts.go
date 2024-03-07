package serviceaccounts

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"

	"github.com/RedHatInsights/mocktitlements/keycloak"
)

var log logr.Logger

func init() {

	zapLog, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("who watches the watchmen (%v)?", err))
	}
	log = zapr.NewLogger(zapLog)
}

type ServiceAccount struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"`
	Secret      string `json:"secret"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedBy   string `json:"createdBy"`
	CreatedAt   string `json:"createdAt"`
}

type serviceAccountSpec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type clientCreateResponse struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"`
	Secret      string `json:"secret"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedBy   string `json:"createdBy"`
	CreatedAt   string `json:"createdAt"`
}

func ServiceAccountHandler(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) {
	switch {
	case r.Method == "GET":
		log.Info(fmt.Sprintf("query params: %s", r.URL.Query()))
		getServiceAccounts(w, r, kc)
	case r.Method == "POST":
		createServiceAccount(w, r, kc)
	}
}

func createServiceAccount(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) {
	var saUser serviceAccountSpec

	defer r.Body.Close()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error(err, "cannot read response body")
	}

	if err := json.Unmarshal(b, &saUser); err != nil {
		log.Error(err, "cannot unmarshal response body")
	}

	clientObject, err := CreateClient(saUser.Name, "12345", kc)
	if err != nil {
		log.Error(err, "bad error")
	}

	outputStruct := clientCreateResponse{
		Name:     clientObject.Name,
		ClientID: clientObject.ClientID,
	}

	outputBytes, err := json.Marshal(outputStruct)
	if err != nil {
		log.Error(err, "There was an error constructing the JSON output object")
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, string(outputBytes))
}

func getServiceAccountQuery(kc *keycloak.Instance, queryString string) ([]keycloak.UsersSpec, error) {
	kcURL, err := url.Parse(kc.URL)
	if err != nil {
		return []keycloak.UsersSpec{}, fmt.Errorf("couldn't parse keycloak url: %w", err)
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
		return []keycloak.UsersSpec{}, fmt.Errorf("couldn't create request: %w", err)
	}

	log.Info(fmt.Sprintf("%v", req))
	resp, err := kc.Client.Do(req)

	if err != nil {
		return []keycloak.UsersSpec{}, fmt.Errorf("couldn't do request: %w", err)
	}

	log.Info(fmt.Sprintf("%v", resp))
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return []keycloak.UsersSpec{}, fmt.Errorf("couldn't read body data: %w", err)
	}

	obj := &[]keycloak.UsersSpec{}
	err = json.Unmarshal(data, obj)

	if err != nil {
		log.Error(err, "could not unmarshal data")
		log.Info(fmt.Sprintf("%v", data))
	}

	return *obj, nil
}

func getServiceAccounts(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) {
	var serviceAccountList []ServiceAccount

	users, err := getServiceAccountQuery(kc, "org_id:"+r.URL.Query().Get("org_id")+" AND boss:true")
	if err != nil {
		log.Error(err, "couldn't get service account")
	}

	for _, user := range users {
		serviceAccountList = append(serviceAccountList, ServiceAccount{
			ID:          "",
			ClientID:    "",
			Secret:      "",
			Name:        user.Username,
			Description: "",
			CreatedBy:   "",
			CreatedAt:   "",
		})
	}

	outputUsers, err := json.Marshal(serviceAccountList)
	fmt.Fprint(w, string(outputUsers))
	w.WriteHeader(http.StatusOK)
}

func deleteServiceAccount(w http.ResponseWriter, r *http.Request, k *http.Client) {
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

func createMapper(attr string, mtype string, multi bool) mapperStruct {
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

type Attributes struct {
	Oauth2       bool   `json:"oauth2.device.authorization.grant.enabled"`
	GrantEnabled bool   `json:"oidc.ciba.grant.enabled"`
	SAML_IDP     string `json:"saml_idp_initiated_sso_url_name"`
}

type clientStruct struct {
	ClientId                  string         `json:"clientId"`
	Name                      string         `json:"name"`
	BearerOnly                bool           `json:"bearerOnly,omitempty"`
	PublicClient              bool           `json:"publicClient"`
	BaseURL                   string         `json:"baseUrl"`
	ProtocolMappers           []mapperStruct `json:"protocolMappers"`
	DirectAccessGrantsEnabled bool           `json:"directAccessGrantsEnabled"`
	Attributes                Attributes     `json:"attributes"`
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

func createClientKeycloak(clientName string, kc *keycloak.Instance) error {
	postObj := clientStruct{
		DisplayInConsole:          false,
		Name:                      "",
		FrontChannelLogout:        true,
		AuthServices:              false,
		ClientId:                  clientName,
		PublicClient:              false,
		DirectAccessGrantsEnabled: false,
		StandardFlow:              false,
		ImplicitFlow:              false,
		Protocol:                  "openid-connect",
		ServiceAccounts:           true,
		Attributes: Attributes{
			Oauth2:       false,
			GrantEnabled: false,
			SAML_IDP:     "",
		},
	}

	b, err := json.Marshal(postObj)
	log.Info(fmt.Sprintf("%s", string(b)))

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

func getClientKeycloak(clientName string, kc *keycloak.Instance) (keycloak.ClientObject, error) {
	resp, err := kc.Client.Get(fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients", kc.URL))
	if err != nil {
		log.Error(err, "could not get client")
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error(err, "could not read body data")
	}

	clientList := []keycloak.ClientObject{}

	err = json.Unmarshal(data, &clientList)
	if err != nil {
		log.Error(err, "could not unmarshal clientid")
	}

	var foundClient keycloak.ClientObject
	for _, kclient := range clientList {
		if kclient.ClientID == clientName {
			foundClient = kclient
			break
		}
	}
	log.Info(fmt.Sprintf("%v", foundClient))
	return foundClient, nil
}

func createMapperKeycloak(id string, kc *keycloak.Instance) error {
	mapperObj := createMapper("org_id", "String", false)

	b, err := json.Marshal(mapperObj)
	log.Info(string(b))

	if err != nil {
		return fmt.Errorf("couldn't marshal post object for mapper: %w", err)
	}

	log.Info(fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/%s/protocol-mappers/models", kc.URL, id))

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

func CreateClient(clientName, orgID string, kc *keycloak.Instance) (*keycloak.ClientObject, error) {

	err := createClientKeycloak(clientName, kc)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not create client: %w", err)
	}

	foundClient, err := getClientKeycloak(clientName, kc)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not find client: %w", err)
	}

	err = createMapperKeycloak(foundClient.ID, kc)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not create mapper: %w", err)
	}

	return &foundClient, nil
}
