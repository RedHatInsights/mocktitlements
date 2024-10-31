package serviceaccounts

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/RedHatInsights/mocktitlements/keycloak"
	"github.com/google/uuid"
	"github.com/redhatinsights/platform-go-middlewares/identity"
)

type ServiceAccount struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"`
	Secret      string `json:"secret"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedBy   string `json:"createdBy"`
	CreatedAt   int64  `json:"createdAt"`
}

type serviceAccountInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func ServiceAccountHandler(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) {
	var err error
	// Default HTTP error status is 500
	httpErrorStatus := http.StatusInternalServerError
	switch {
	case r.Method == "GET":
		// To match production 404 should be returned if
		// a bogus service account is requested
		httpErrorStatus = http.StatusNotFound
		kc.Log.Info(fmt.Sprintf("query params: %s", r.URL.Query()))
		err = getServiceAccounts(w, r, kc)
	case r.Method == "POST":
		err = createServiceAccount(w, r, kc)
	case r.Method == "DELETE":
		err = deleteServiceAccount(w, r, kc)
	case r.Method == "OPTIONS":
		err = optionsServiceAccount(w, r)
	}
	if err != nil {
		errString := fmt.Sprintf("%s", err)
		kc.Log.Error(err, "error running function: ")
		http.Error(w, errString, httpErrorStatus)
	}
}

func applyHeaders(w http.ResponseWriter) {
	w.Header().Add("access-control-allow-credentials", "true")
	w.Header().Add("access-control-allow-headers", "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, DPoP, Authorization")
	w.Header().Add("access-control-allow-methods", "DELETE, POST, GET, PUT, PATCH")
	w.Header().Add("access-control-allow-origin", "*")
	w.Header().Add("access-control-max-age", "3600")
}

func optionsServiceAccount(w http.ResponseWriter, _ *http.Request) error {
	applyHeaders(w)
	return nil
}

func createServiceAccount(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) error {
	var saUser serviceAccountInput

	orgID, createdBy, err := getOrgInfo(r)
	if err != nil {
		return fmt.Errorf("couldn't get orgid: %w", err)
	}

	defer r.Body.Close()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("cannot read response body: %w", err)
	}

	if err := json.Unmarshal(b, &saUser); err != nil {
		return fmt.Errorf("cannot unmarshal response body: %w", err)
	}

	serviceAccount, err := CreateServiceAccount(saUser.Name, orgID, createdBy, saUser.Description, kc)
	if err != nil {
		return fmt.Errorf("bad error: %w", err)
	}

	outputBytes, err := json.Marshal(serviceAccount)
	if err != nil {
		return fmt.Errorf("there was an error constructing the JSON output object: %w", err)
	}

	w.Header().Add("access-control-allow-origin", "*")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, string(outputBytes))
	return nil
}

func getOrgInfo(r *http.Request) (string, string, error) {
	xrhid := r.Header.Get("x-rh-identity")
	output, err := base64.StdEncoding.DecodeString(xrhid)

	if err != nil {
		return "", "", fmt.Errorf("error obtaining xrhid: %w", err)
	}

	xrhidObject := &identity.XRHID{}
	err = json.Unmarshal(output, xrhidObject)

	if err != nil {
		return "", "", fmt.Errorf("error unmarshalling xrhid: %w", err)
	}

	return xrhidObject.Identity.Internal.OrgID, xrhidObject.Identity.User.Username, nil
}

func getServiceAccountList(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) error {
	var serviceAccountList = []ServiceAccount{}

	orgID, _, err := getOrgInfo(r)
	if err != nil {
		return fmt.Errorf("couldn't get orgid: %w", err)
	}

	users, err := kc.GetServiceAccountQuery("org_id:"+orgID+" AND service_account:true", r.URL.Query())
	if err != nil {
		return fmt.Errorf("couldn't get service account: %w", err)
	}

	for _, user := range users {

		secret, err := kc.GetClientSecret(user.Attributes["client_id"][0])
		if err != nil {
			return fmt.Errorf("unable to get client secrets: %w", err)
		}

		serviceAccountList = append(serviceAccountList, ServiceAccount{
			ID:          user.Attributes["client_id"][0],
			ClientID:    user.Attributes["client_id"][0],
			Secret:      secret,
			Name:        user.Username,
			Description: user.Attributes["description"][0],
			CreatedBy:   user.Attributes["created_by"][0],
			CreatedAt:   user.CreatedTimestamp,
		})
	}

	outputUsers, err := json.Marshal(serviceAccountList)
	if err != nil {
		return fmt.Errorf("couldn't marshal serviceAccountList: %w", err)
	}
	w.Header().Add("access-control-allow-origin", "*")
	fmt.Fprint(w, string(outputUsers))
	return nil
}

func getSingleServiceAccount(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance, uuid string) error {
	orgID, _, err := getOrgInfo(r)
	if err != nil {
		return fmt.Errorf("couldn't get orgid: %w", err)
	}

	users, err := kc.GetServiceAccountQuery("org_id:"+orgID+" AND service_account:true AND client_id:"+uuid, r.URL.Query())
	if err != nil {
		return fmt.Errorf("couldn't get service account: %w", err)
	}

	if len(users) != 1 {
		return fmt.Errorf("too many/few service accounts: %w", err)
	}

	user := users[0]

	secret, err := kc.GetClientSecret(user.Attributes["client_id"][0])
	if err != nil {
		return fmt.Errorf("unable to get client secrets: %w", err)
	}

	serviceAccount := ServiceAccount{
		ID:          user.Attributes["client_id"][0],
		ClientID:    user.Attributes["client_id"][0],
		Secret:      secret,
		Name:        user.Username,
		Description: user.Attributes["description"][0],
		CreatedBy:   user.Attributes["created_by"][0],
		CreatedAt:   user.CreatedTimestamp,
	}

	outputUsers, err := json.Marshal(serviceAccount)
	if err != nil {
		return fmt.Errorf("couldn't marshal serviceAccountList: %w", err)
	}
	w.Header().Add("access-control-allow-origin", "*")
	fmt.Fprint(w, string(outputUsers))
	return nil
}

func getServiceAccounts(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) error {
	parts := strings.Split(r.URL.Path, "/")
	lastPart := parts[len(parts)-1]

	// Try to parse as UUID
	if _, err := uuid.Parse(lastPart); err == nil {
		return getSingleServiceAccount(w, r, kc, lastPart)
	}

	// Check if any query parameters are present
	if len(r.URL.Query()) > 0 {
		return getServiceAccountList(w, r, kc)
	}

	// If neither UUID nor query string, return an error response
	http.Error(w, "Malformed input: expected UUID or query parameters", http.StatusBadRequest)
	return fmt.Errorf("malformed input: neither UUID nor query parameters")
}

func deleteServiceAccount(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) error {
	kc.Log.Info(fmt.Sprintf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL))

	parts := strings.Split(r.URL.Path, "/")

	var id string

	// Check if the path matches the beginning
	expectedPath := "/auth/realms/redhat-external/apis/service_accounts/v1"
	if strings.HasPrefix(r.URL.Path, expectedPath) {
		// Extract the ID from the end
		id = parts[len(parts)-1]
	} else {
		return fmt.Errorf("path does not match the beginning: %s", expectedPath)
	}

	path := r.URL
	path.Path = fmt.Sprintf("/auth/admin/realms/redhat-external/clients/%s", id)

	body := strings.NewReader("")
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s%s", kc.URL, r.URL), body)
	if err != nil {
		return fmt.Errorf("couldn't create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	resp, err := kc.Client.Do(req)
	if err != nil {
		return fmt.Errorf("couldn't do delete: %w", err)
	}
	if resp.StatusCode == 404 {
		return fmt.Errorf("not found")
	}
	if resp.StatusCode != 204 {
		return fmt.Errorf("problem deleting: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	kc.Log.Info(fmt.Sprintf("%v", resp))
	w.Header().Add("access-control-allow-origin", "*")
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type MapperAttribute struct {
	name         string
	mapperType   string
	isMultiValue bool
}

func createMapperAttribute(name, mapperType string, isMultiValue bool) MapperAttribute {
	return MapperAttribute{
		name:         name,
		mapperType:   mapperType,
		isMultiValue: isMultiValue,
	}
}

func CreateServiceAccount(clientName, orgID, createdBy, description string, kc *keycloak.Instance) (*ServiceAccount, error) {

	uuid := uuid.New().String()
	err := kc.CreateClient(clientName, uuid)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("could not create client: %w", err)
	}

	foundClient, err := kc.GetClient(uuid)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("could not find client: %w", err)
	}

	attributes := []MapperAttribute{
		createMapperAttribute("org_id", "String", false),
		createMapperAttribute("service_account", "String", false),
		createMapperAttribute("client_id", "String", false),
		createMapperAttribute("created_by", "String", false),
		createMapperAttribute("description", "String", false),
		createMapperAttribute("newEntitlements", "String", true),
	}

	for _, attr := range attributes {
		err = kc.CreateMapper(foundClient.ClientID, attr.name, attr.mapperType, attr.isMultiValue)
		if err != nil {
			return &ServiceAccount{}, fmt.Errorf("could not create [%s] mapper: %w", attr.name, err)
		}
	}

	foundServiceAccount, err := kc.GetServiceUser(foundClient.ClientID)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("could not find clients service account: %w", err)
	}

	user, err := kc.FindUserByID(createdBy)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("unable to retrieve user from keycloak: %w", err)
	}

	attrs := map[string][]string{
		"org_id":          {orgID},
		"service_account": {"true"},
		"client_id":       {foundClient.ClientID},
		"created_by":      {createdBy},
		"description":     {description},
		"newEntitlements": user.Entitlements,
	}

	err = kc.AddServiceUserAttributes(attrs, foundServiceAccount.ID)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("unable to add attributes: %w", err)
	}

	serviceAccount := ServiceAccount{
		Name:        foundServiceAccount.Username,
		ClientID:    foundClient.ClientID,
		Secret:      foundClient.Secret,
		CreatedAt:   foundServiceAccount.CreatedTimestamp,
		ID:          foundClient.ClientID,
		CreatedBy:   createdBy,
		Description: description,
	}

	return &serviceAccount, nil
}
