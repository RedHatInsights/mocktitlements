package serviceaccounts

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/RedHatInsights/mocktitlements/keycloak"
)

type ServiceAccount struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"`
	Secret      string `json:"secret"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedBy   string `json:"createdBy"`
	CreatedAt   string `json:"createdAt"`
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

	defer r.Body.Close()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("cannot read response body: %w", err)
	}

	if err := json.Unmarshal(b, &saUser); err != nil {
		return fmt.Errorf("cannot unmarshal response body: %w", err)
	}

	clientObject, err := CreateServiceAccount(saUser.Name, "12345", kc)
	if err != nil {
		return fmt.Errorf("bad error: %w", err)
	}

	outputStruct := ServiceAccount{
		Name:     clientObject.Name,
		ClientID: clientObject.ClientID,
	}

	outputBytes, err := json.Marshal(outputStruct)
	if err != nil {
		return fmt.Errorf("there was an error constructing the JSON output object: %w", err)
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, string(outputBytes))
	return nil
}

func getServiceAccounts(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) error {
	var serviceAccountList []ServiceAccount

	users, err := kc.GetServiceAccountQuery("org_id:" + r.URL.Query().Get("org_id") + " AND service_account:true")
	if err != nil {
		return fmt.Errorf("couldn't get service account: %w", err)
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

func CreateServiceAccount(clientName, orgID string, kc *keycloak.Instance) (*keycloak.ClientObject, error) {

	err := kc.CreateClient(clientName, orgID)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not create client: %w", err)
	}

	foundClient, err := kc.GetClient(clientName)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not find client: %w", err)
	}

	err = kc.CreateMapper(foundClient.ID, "org_id", "String")
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not create org_id mapper: %w", err)
	}
	err = kc.CreateMapper(foundClient.ID, "service_account", "String")
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not create service_accounts mapper: %w", err)
	}

	foundServiceAccount, err := kc.GetServiceUser(foundClient.ID)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not find clients service account: %w", err)
	}

	attrs := map[string]string{
		"org_id":          orgID,
		"service_account": "true",
	}

	err = kc.AddServiceAccountAttributes(attrs, foundServiceAccount.ID)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("unable to add attributes: %w", err)
	}

	return &foundClient, nil
}
