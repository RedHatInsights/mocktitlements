package serviceaccounts

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-logr/logr"
)

var log logr.Logger

var KeyCloakServer string
var KeyCloakUsername string
var KeyCloakPassword string

func init() {
	KeyCloakServer = os.Getenv("KEYCLOAK_SERVER")
	KeyCloakUsername = os.Getenv("KEYCLOAK_USERNAME")
	KeyCloakPassword = os.Getenv("KEYCLOAK_PASSWORD")
	if KeyCloakUsername == "" {
		KeyCloakUsername = "admin"
	}
	if KeyCloakPassword == "" {
		KeyCloakPassword = "admin"
	}
}

type ServiceAccounts struct {
	Username      string `json:"username"`
	ID            int    `json:"id"`
	Email         string `json:"email"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	AccountNumber string `json:"account_number"`
	AddressString string `json:"address_string"`
	IsActive      bool   `json:"is_active"`
	IsOrgAdmin    bool   `json:"is_org_admin"`
	IsInternal    bool   `json:"is_internal"`
	Locale        string `json:"locale"`
	OrgID         int    `json:"org_id"`
	DisplayName   string `json:"display_name"`
	Type          string `json:"type"`
	Entitlements  string `json:"entitlements"`
}

type serviceAccountSpec struct {
	Username   string              `json:"username"`
	Enabled    bool                `json:"enabled"`
	FirstName  string              `json:"firstName"`
	LastName   string              `json:"lastName"`
	Email      string              `json:"email"`
	Attributes map[string][]string `json:"attributes"`
}

func ServiceAccountHandler(w http.ResponseWriter, r *http.Request, k *http.Client) {
	switch {
	case r.Method == "GET":
		log.Info(fmt.Sprintf("%v\n", r))
		GetServiceAccounts(w, r, k)
	}
}

func GetServiceAccounts(w http.ResponseWriter, r *http.Request, k *http.Client) {
	log.Info(fmt.Sprintf("%v\n", r))
	resp, err := k.Get(KeyCloakServer + "/auth/realms/redhat-external/apis/service_accounts/v1?first=0&max=100")
	if err != nil {
		fmt.Printf("\n\n%s\n\n", err.Error())
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
	}

	log.Info(fmt.Sprintf("%s\n", data))
}
