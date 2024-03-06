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

	outputStruct := clientCreateResponse{
		Name: saUser.Name,
	}

	outputBytes, err := json.Marshal(outputStruct)
	if err != nil {
		log.Error(err, "There was an error constructing the JSON output object")
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, string(outputBytes))
}

func getServiceAccounts(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) {
	var serviceAccountList []ServiceAccount

	kcURL, err := url.Parse(kc.URL)
	if err != nil {
		log.Error(err, "couldn't parse keycloak url")
	}

	query := url.Values{}
	query.Set("enabled", "true")
	query.Set("first", "0")
	query.Set("max", "51")
	query.Set("q", "org_id:"+r.URL.Query().Get("org_id")+" AND boss:true")

	murl := url.URL{
		Scheme:   kcURL.Scheme,
		Host:     kcURL.Host,
		Path:     "auth/admin/realms/redhat-external/users",
		RawQuery: query.Encode(),
	}
	re := strings.NewReader("")

	req, err := http.NewRequest("GET", murl.String(), re)

	log.Info(fmt.Sprintf("%v", req))
	resp, err := kc.Client.Do(req)
	
	if err != nil {
		log.Error(err, "couldn't do request")
	}
	log.Info(fmt.Sprintf("%v", resp))
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error(err, "could not read body data")
	}

	obj := &[]keycloak.UsersSpec{}
	err = json.Unmarshal(data, obj)

	if err != nil {
		log.Error(err, "could not unmarshal data")
		log.Info(fmt.Sprintf("%v", data))
	}

	for _, user := range *obj {
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
