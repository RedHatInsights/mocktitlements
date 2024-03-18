package main

import (
	"testing"

	"github.com/RedHatInsights/mocktitlements/keycloak"
	"github.com/go-logr/logr"
)

func TestGetUsersBadJSON(t *testing.T) {
	str := `{"username":"jd"}`
	data := []byte(str)

	_, err := keycloak.ParseUsers(logr.Discard(), data)

	if err == nil {
		t.Errorf("Error should have been generated")
	}
}

func TestIncompleteAttributes(t *testing.T) {
	str := `[{
		"username": "jd",
		"enabled": true,
		"firstName": "jd",
		"lastName": "dj",
		"email": "jddj@redhat.com",
		"attributes": {
			"test": ["test"]
		}
	}]`

	data := []byte(str)
	users, err := keycloak.ParseUsers(logr.Discard(), data)
	if err != nil {
		t.Errorf("Error should not have been generated")
	}
	if len(users) > 0 {
		t.Errorf("User should have been filtered out")
	}
}

func TestValidUser(t *testing.T) {
	str := `[{
		"username": "jd",
		"enabled": true,
		"firstName": "jd",
		"lastName": "dj",
		"email": "jddj@redhat.com",
		"attributes": {
			"is_internal": ["true"],
			"is_org_admin": ["true"],
			"is_active": ["true"],
			"account_id": ["1"],
			"org_id": ["1"],
			"account_number": ["1"],
			"entitlements": [""]
		}
	},
	{
		"username": "jd2",
		"enabled": true,
		"firstName": "jd",
		"lastName": "dj",
		"email": "jddj@redhat.com",
		"attributes": {
			"is_internal": ["true"],
			"is_org_admin": ["true"],
			"is_active": ["true"],
			"account_id": ["1"],
			"org_id": ["1"],
			"account_number": ["1"],
			"entitlements": [""]
		}
	}]`

	data := []byte(str)
	users, err := keycloak.ParseUsers(logr.Discard(), data)
	if err != nil {
		t.Errorf("Error should not have been generated: %s", err)
	}
	if len(users) != 2 {
		t.Errorf("Users count should be 2")
	}
}
