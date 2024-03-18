package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"

	"github.com/RedHatInsights/mocktitlements/keycloak"
	sa "github.com/RedHatInsights/mocktitlements/serviceaccounts"
)

var log logr.Logger
var kc *keycloak.Instance

func init() {

	zapLog, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("who watches the watchmen (%v)?", err))
	}
	log = zapr.NewLogger(zapLog)
}

func main() {
	kc = keycloak.GetKeycloakInstance(log)
	http.HandleFunc("/", mainHandler)
	server := http.Server{
		Addr:              ":8090",
		ReadHeaderTimeout: 2 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Error(err, "CouldNotStart", "reason", "server couldn't start")
	}
}

func Entitlements(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) {
	userObj, err := kc.GetUser(w, r)

	if err != nil {
		http.Error(w, fmt.Sprintf("couldn't auth user: %s", err.Error()), http.StatusForbidden)
		return
	}

	fmt.Fprint(w, userObj.Entitlements)
}

func Compliance(w http.ResponseWriter, r *http.Request, kc *keycloak.Instance) {
	_, err := kc.GetUser(w, r)

	if err != nil {
		http.Error(w, fmt.Sprintf("couldn't auth user: %s", err.Error()), http.StatusForbidden)
		return
	}

	fmt.Fprint(w, "\"result\": \"OK\"\n\"description\":\"\" ")
}

// MUST VALIDATE THAT THE BEARER TOKEN HAD THE RIGHT SCOPES
func mainHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(fmt.Sprintf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL))
	switch {
	case r.URL.Path == "/":
		kc.StatusHandler(w, r)
	case r.URL.Path == "/api/entitlements/v1/services":
		Entitlements(w, r, kc)
	case r.URL.Path == "/api/entitlements/v1/compliance":
		Compliance(w, r, kc)
	case strings.Contains(r.URL.Path, "/auth/"):
		sa.ServiceAccountHandler(w, r, kc)
	}
}
