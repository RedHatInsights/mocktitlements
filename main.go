package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	keycloak "github.com/RedHatInsights/simple-kc-client"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/redhatinsights/platform-go-middlewares/identity"
	"go.uber.org/zap"
)

var log logr.Logger

func init() {

	zapLog, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("who watches the watchmen (%v)?", err))
	}
	log = zapr.NewLogger(zapLog)
}

func getUserFromIdentity(r *http.Request) (*User, error) {
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

	user, err := findUserById(identity.Identity.User.Username)
	if err != nil {
		return &User{}, err
	}

	return user, nil
}

type User struct {
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

var KEYCLOAK_SERVER string
var KEYCLOAK_USERNAME string
var KEYCLOAK_PASSWORD string
var KEYCLOAK_VERSION string

func init() {
	KEYCLOAK_SERVER = os.Getenv("KEYCLOAK_SERVER")
	KEYCLOAK_USERNAME = os.Getenv("KEYCLOAK_USERNAME")
	KEYCLOAK_PASSWORD = os.Getenv("KEYCLOAK_PASSWORD")
	KEYCLOAK_VERSION = os.Getenv("KEYCLOAK_VERSION")
	if KEYCLOAK_USERNAME == "" {
		KEYCLOAK_USERNAME = "admin"
	}
	if KEYCLOAK_PASSWORD == "" {
		KEYCLOAK_PASSWORD = "admin"
	}
	if KEYCLOAK_VERSION == "" {
		KEYCLOAK_VERSION = "11.0.0"
	}
}

func findUserById(username string) (*User, error) {
	users, err := getUsers()

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

func getUser(w http.ResponseWriter, r *http.Request) (*User, error) {
	userObj, err := getUserFromIdentity(r)

	if err != nil {
		return &User{}, fmt.Errorf("couldn't find user: %s", err.Error())
	}
	return userObj, nil
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
}

type usersSpec struct {
	Username   string              `json:"username"`
	Enabled    bool                `json:"enabled"`
	FirstName  string              `json:"firstName"`
	LastName   string              `json:"lastName"`
	Email      string              `json:"email"`
	Attributes map[string][]string `json:"attributes"`
}

func getUsers() (users []User, err error) {
	resp, err := k.Get("/admin/realms/redhat-external/users?max=2000", "", map[string]string{})
	if err != nil {
		fmt.Printf("\n\n%s\n\n", err.Error())
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseUsers(data)
}

func parseUsers(data []byte) ([]User, error) {
	obj := &[]usersSpec{}

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

		var entitle string

		if len(user.Attributes["newEntitlements"]) != 0 {
			entitle = fmt.Sprintf("{%s}", strings.Join(user.Attributes["newEntitlements"], ","))

		} else {
			entitle = user.Attributes["entitlements"][0]
		}

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
			Entitlements:  entitle,
		})
	}

	return users, nil
}

func entitlements(w http.ResponseWriter, r *http.Request) {
	userObj, err := getUser(w, r)

	if err != nil {
		http.Error(w, fmt.Sprintf("couldn't auth user: %s", err.Error()), http.StatusForbidden)
		return
	}

	fmt.Fprint(w, string(userObj.Entitlements))
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(fmt.Sprintf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL))
	switch {
	case r.URL.Path == "/":
		statusHandler(w, r)
	case r.URL.Path == "/api/entitlements/v1/services":
		entitlements(w, r)
	case r.URL.Path == "/api/entitlements/v1/compliance":
		entitlements(w, r)
	}
}

var k *keycloak.KeyCloakClient

func main() {
	key, err := keycloak.NewKeyCloakClient(KEYCLOAK_SERVER, KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD, context.Background(), "master", log, KEYCLOAK_VERSION)

	k = key

	if err != nil {
		log.Error(err, "reason", "couldn't connect")
	}
	http.HandleFunc("/", mainHandler)

	if err = http.ListenAndServe(":8090", nil); err != nil {
		log.Error(err, "reason", "server couldn't start")
	}
}
