package serviceaccounts

import (
	"strings"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
	switch {
	case r.Method == "GET":
		kc.Log.Info(fmt.Sprintf("query params: %s", r.URL.Query()))
		getServiceAccounts(w, r, kc)
	case r.Method == "POST":
		createServiceAccount(w, r, kc)
	case r.Method == "DELETE":
		deleteServiceAccount(w, r, kc)
	}
}

func createServiceAccount(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) {
	var saUser serviceAccountInput

	defer r.Body.Close()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		kc.Log.Error(err, "cannot read response body")
	}

	if err := json.Unmarshal(b, &saUser); err != nil {
		kc.Log.Error(err, "cannot unmarshal response body")
	}

	clientObject, err := CreateServiceAccount(saUser.Name, "12345", kc)
	if err != nil {
		kc.Log.Error(err, "bad error")
	}

	outputStruct := ServiceAccount{
		Name:     clientObject.Name,
		ClientID: clientObject.ClientID,
	}

	outputBytes, err := json.Marshal(outputStruct)
	if err != nil {
		kc.Log.Error(err, "There was an error constructing the JSON output object")
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, string(outputBytes))
}

func getServiceAccounts(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) {
	var serviceAccountList []ServiceAccount

	users, err := kc.GetServiceAccountQuery("org_id:" + r.URL.Query().Get("org_id") + " AND boss:true")
	if err != nil {
		kc.Log.Error(err, "couldn't get service account")
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
		kc.Log.Error(err, "couldn't marshal serviceAccountList")
	}
	fmt.Fprint(w, string(outputUsers))
	w.WriteHeader(http.StatusOK)
}

func deleteServiceAccount(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) error {
	kc.Log.Info(fmt.Sprintf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL))
	
	body := strings.NewReader("")
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/auth/admin/realms/redhat-external/clients/d0e03e99-28c9-40f5-9f7b-09cd027f35af", kc.URL), body)
	if err != nil {
		return fmt.Errorf("couldn't create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	_, err = kc.Client.Do(req)
	if err != nil {
		return fmt.Errorf("couldn't do delete: %w", err)
	}

	kc.Log.Info("successfully deleted service account [5d0b0422-5974-4152-9e29-4866820a1990]")

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func CreateServiceAccount(clientName, orgID string, kc *keycloak.Instance) (*keycloak.ClientObject, error) {

	err := kc.CreateClient(clientName)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not create client: %w", err)
	}

	foundClient, err := kc.GetClient(clientName)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not find client: %w", err)
	}

	err = kc.CreateMapper(foundClient.ID)
	if err != nil {
		return &keycloak.ClientObject{}, fmt.Errorf("could not create mapper: %w", err)
	}

	return &foundClient, nil
}
