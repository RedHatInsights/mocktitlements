package main

import (
	"testing"

	"github.com/RedHatInsights/mocktitlements/keycloak"
	"github.com/go-logr/logr"
)

func TestIncompleteAttributes(t *testing.T) {
	usersspec := &[]keycloak.UsersSpec{{
		Username:  "jd",
		Enabled:   true,
		FirstName: "jd",
		LastName:  "dj",
		Email:     "jddj@redhat.com",
		Attributes: map[string][]string{
			"test": {"test"},
		},
	}}

	users, err := keycloak.ParseUsers(logr.Discard(), usersspec)
	if err != nil {
		t.Errorf("Error should not have been generated")
	}
	if len(users) > 0 {
		t.Errorf("User should have been filtered out")
	}
}

func TestValidUser(t *testing.T) {
	usersspec := &[]keycloak.UsersSpec{{
		Username:  "jd",
		Enabled:   true,
		FirstName: "jd",
		LastName:  "dj",
		Email:     "jddj@redhat.com",
		Attributes: map[string][]string{
			"is_internal":    {"true"},
			"is_org_admin":   {"true"},
			"is_active":      {"true"},
			"account_id":     {"1"},
			"org_id":         {"1"},
			"account_number": {"1"},
			"entitlements":   {""},
		},
	}, {
		Username:  "jd2",
		Enabled:   true,
		FirstName: "jd",
		LastName:  "dj",
		Email:     "jddj@redhat.com",
		Attributes: map[string][]string{
			"is_internal":    {"true"},
			"is_org_admin":   {"true"},
			"is_active":      {"true"},
			"account_id":     {"1"},
			"org_id":         {"1"},
			"account_number": {"1"},
			"entitlements":   {""},
		},
	}}

	users, err := keycloak.ParseUsers(logr.Discard(), usersspec)
	if err != nil {
		t.Errorf("Error should not have been generated: %s", err)
	}
	if len(users) != 2 {
		t.Errorf("Users count should be 2")
	}
}
