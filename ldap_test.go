package gw

import (
	"testing"
)

func setupLDAP() LDAPConfiguration {
	return LDAP{
		Host:         "ldapserver.example.com",
		Port:         389,
		BindUsername: "cn=binduser,dc=example,dc=com",
		BindPassword: "abcdefgh",
		BaseDN:       "dc=example,dc=com",
		UserDN:       "ou=users,dc=example,dc=com",
		GroupDN:      "ou=grps,dc=example,dc=com",
	}
}

func TestUsernameToDN(t *testing.T) {
	l := setupLDAP()
	u := l.UsernameToDN("tester")
	if u != "uid=tester,ou=users,dc=example,dc=com" {
		t.Errorf("Incorrect DN returned: %s", u)
	}
}

func TestGroupnameToDN(t *testing.T) {
	l := setupLDAP()
	g := l.GroupnameToDN("testers")
	if g != "cn=testers,ou=grps,dc=example,dc=com" {
		t.Errorf("Incorrect DN returned: %s", g)
	}
}

func TestFormatServer(t *testing.T) {
	l := setupLDAP()
	s := l.FormatServer()
	if s != "ldapserver.example.com:389" {
		t.Error("Not formatting server properly: %s", s)
	}
}

// Bail, not a great way to test this at the moment.
func TestAuth(t *testing.T) {
	t.Skip()
}

// Bail, not a great way to test this at the moment.
func TestAuthenticate(t *testing.T) {
	t.Skip()
}
