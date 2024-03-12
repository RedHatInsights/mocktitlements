package serviceaccounts

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/RedHatInsights/mocktitlements/keycloak"
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

	switch {
	case r.Method == "GET":
		kc.Log.Info(fmt.Sprintf("query params: %s", r.URL.Query()))
		err = getServiceAccounts(w, r, kc)
	case r.Method == "POST":
		err = createServiceAccount(w, r, kc)
	case r.Method == "DELETE":
		err = deleteServiceAccount(w, r, kc)
	}
	if err != nil {
		errString := fmt.Sprintf("%s", err)
		kc.Log.Error(err, "error running function: ")
		http.Error(w, errString, http.StatusInternalServerError)
	}
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

func getServiceAccounts(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) error {
	var serviceAccountList []ServiceAccount

	orgID, _, err := getOrgInfo(r)
	if err != nil {
		return fmt.Errorf("couldn't get orgid: %w", err)
	}

	users, err := kc.GetServiceAccountQuery("org_id:" + orgID + " AND service_account:true")
	if err != nil {
		return fmt.Errorf("couldn't get service account: %w", err)
	}

	for _, user := range users {

		secret, err := kc.GetClientSecret(user.Attributes["client_id"][0])
		if err != nil {
			return fmt.Errorf("unable to get client secrets: %w", err)
		}

		serviceAccountList = append(serviceAccountList, ServiceAccount{
			ID:          user.ID,
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
	fmt.Fprint(w, string(outputUsers))
	return nil
}

func deleteServiceAccount(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) error {
	kc.Log.Info(fmt.Sprintf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL))

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
	defer resp.Body.Close()

	kc.Log.Info(fmt.Sprintf("%v", resp))

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func CreateServiceAccount(clientName, orgID, createdBy, description string, kc *keycloak.Instance) (*ServiceAccount, error) {

	err := kc.CreateClient(clientName, orgID)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("could not create client: %w", err)
	}

	// We can't use our own nice client lookup, because it relies on us having the client ID, which
	// we don't have at this point, so we use the name. This GetClient function can be optimized to not
	// have the loop by using new parameters for the search, these are not the same as the `q` parameter
	// used in the users call.
	foundClient, err := kc.GetClient(clientName)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("could not find client: %w", err)
	}

	attributes := map[string]string{
		"org_id":          "String",
		"service_account": "String",
		"client_id":       "String",
		"created_by":      "String",
		"description":     "String",
	}
	for k, v := range attributes {
		err = kc.CreateMapper(foundClient.ClientID, k, v)
		if err != nil {
			return &ServiceAccount{}, fmt.Errorf("could not create [%s] mapper: %w", k, err)
		}
	}

	foundServiceAccount, err := kc.GetServiceUser(foundClient.ClientID)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("could not find clients service account: %w", err)
	}

	attrs := map[string]string{
		"org_id":          orgID,
		"service_account": "true",
		"client_id":       foundClient.ClientID,
		"created_by":      createdBy,
		"description":     description,
	}

	err = kc.AddServiceUserAttributes(attrs, foundServiceAccount.ID)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("unable to add attributes: %w", err)
	}

	secret, err := kc.GetClientSecret(foundClient.ClientID)
	if err != nil {
		return &ServiceAccount{}, fmt.Errorf("unable to get client secrets: %w", err)
	}

	foundClient.Secret = secret

	serviceAccount := ServiceAccount{
		Name:        foundServiceAccount.Username,
		ClientID:    foundClient.ClientID,
		Secret:      foundClient.Secret,
		CreatedAt:   foundServiceAccount.CreatedTimestamp,
		ID:          foundServiceAccount.ID,
		CreatedBy:   createdBy,
		Description: description,
	}

	return &serviceAccount, nil
}
