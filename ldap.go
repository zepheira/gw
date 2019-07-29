package gw

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/juju/errors"
	"gopkg.in/ldap.v2"
	"regexp"
)

const (
	ADMIN_LOCKED_TIME = "000001010000Z"
)

type LDAPConfiguration interface {
	GetHost() string
	GetPort() uint
	GetBindUsername() string
	GetBindPassword() string
	GetForgotUsername() string
	GetForgotPassword() string
	GetAdminGroup() string
	GetBaseDN() string
	GetUserDN() string
	GetGroupDN() string
	UsernameToDN(string) string
	GroupnameToDN(string) string
	DNToUsername(string) string
	DNToGroupname(string) string
	FormatServer() string
	Auth(string, string) (bool, error)
	GetUser(string) (*LDAPUser, error)
	GetGroup(string) (*LDAPGroup, error)
	CreateUser(*LDAPUser, string, *LDAPCredentials) error
	EditUser(*LDAPUser, *LDAPCredentials) error
	EnableUser(*LDAPUser, *LDAPCredentials) error
	DisableUser(*LDAPUser, *LDAPCredentials, string) error
	IsMember(string, string) (bool, error)
	CreateGroup(*LDAPGroup, *LDAPCredentials) error
	EditGroup(*LDAPGroup, *LDAPCredentials) error
	AddMember(*LDAPGroup, *LDAPUser, *LDAPCredentials) error
	RemoveMember(*LDAPGroup, *LDAPUser, *LDAPCredentials) error
	AddOwner(*LDAPGroup, *LDAPUser, *LDAPCredentials) error
	RemoveOwner(*LDAPGroup, *LDAPUser, *LDAPCredentials) error
	SetPassword(*LDAPUser, string, string) error
	SetForgotPassword(*LDAPUser, string) error
	SynchronizeAll(SyncReceiver) error
}

type SyncReceiver interface {
	OnUser(*LDAPUser) error
	OnGroup(*LDAPGroup) error
}

type LDAP struct {
	Host           string
	Port           uint
	BindUsername   string
	BindPassword   string
	ForgotUsername string
	ForgotPassword string
	AdminGroup     string
	BaseDN         string
	UserDN         string
	GroupDN        string
}

type LDAPUser struct {
	DN         string
	Username   string
	FirstName  string
	LastName   string
	Email      string
	IsActive   bool
	IsAdmin    bool
	LockedTime string
	Groups     []string
}

type LDAPGroup struct {
	DN        string
	Groupname string
	Name      string
	Owners    []string
	Members   []string
}

type LDAPCredentials struct {
	DN       string
	Password string
}

func (l LDAP) GetHost() string {
	return l.Host
}

func (l LDAP) GetPort() uint {
	return l.Port
}

func (l LDAP) GetBindUsername() string {
	return l.BindUsername
}

func (l LDAP) GetBindPassword() string {
	return l.BindPassword
}

func (l LDAP) GetForgotUsername() string {
	return l.ForgotUsername
}

func (l LDAP) GetForgotPassword() string {
	return l.ForgotPassword
}

func (l LDAP) GetAdminGroup() string {
	return l.AdminGroup
}

func (l LDAP) GetBaseDN() string {
	return l.BaseDN
}

func (l LDAP) GetUserDN() string {
	return l.UserDN
}

func (l LDAP) GetGroupDN() string {
	return l.GroupDN
}

func (l LDAP) UsernameToDN(username string) string {
	return fmt.Sprintf("uid=%s,%s", username, l.GetUserDN())
}

func (l LDAP) GroupnameToDN(groupname string) string {
	return fmt.Sprintf("cn=%s,%s", groupname, l.GetGroupDN())
}

func (l LDAP) DNToUsername(dn string) string {
	r, _ := regexp.Compile(fmt.Sprintf("^uid=([^,]+),%s$", l.GetUserDN()))
	matches := r.FindStringSubmatch(dn)
	if len(matches) >= 1 {
		return matches[1]
	} else {
		return ""
	}
}

func (l LDAP) DNToGroupname(dn string) string {
	r, _ := regexp.Compile(fmt.Sprintf("^cn=([^,]+),%s$", l.GetGroupDN()))
	matches := r.FindStringSubmatch(dn)
	if len(matches) >= 1 {
		return matches[1]
	} else {
		return ""
	}
}

func (l LDAP) FormatServer() string {
	return fmt.Sprintf("%s:%d", l.GetHost(), l.GetPort())
}

func (l LDAP) Setup(bind bool) (*ldap.Conn, error) {
	var c *ldap.Conn
	var err error

	c, err = ldap.Dial("tcp", l.FormatServer())
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = c.StartTLS(&tls.Config{ServerName: l.GetHost()})
	if err != nil {
		return nil, errors.Trace(err)
	}

	if bind {
		err = c.Bind(l.GetBindUsername(), l.GetBindPassword())
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	return c, nil
}

func (l LDAP) Auth(user, pass string) (bool, error) {
	c, err := l.Setup(true)
	if err != nil {
		return false, errors.Trace(err)
	}
	defer c.Close()

	search := ldap.NewSearchRequest(
		l.GetUserDN(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", user),
		[]string{"uid"},
		nil)

	sr, err := c.Search(search)
	if err != nil {
		return false, errors.Trace(err)
	}

	if len(sr.Entries) != 1 {
		return false, nil
	}

	userdn := sr.Entries[0].DN

	err = c.Bind(userdn, pass)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func (l LDAP) GetUser(username string) (*LDAPUser, error) {
	c, err := l.Setup(true)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer c.Close()

	search := ldap.NewSearchRequest(
		l.GetUserDN(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", username),
		[]string{"uid", "mail", "givenName", "sn", "pwdAccountLockedTime", "memberOf"},
		nil)

	sr, err := c.Search(search)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if len(sr.Entries) != 1 {
		return nil, errors.Errorf("No such user %s", username)
	}

	active := true
	if sr.Entries[0].GetAttributeValue("pwdAccountLockedTime") != "" {
		active = false
	}

	groups := make([]string, len(sr.Entries[0].GetAttributeValues("memberOf")))
	admin := false
	if len(sr.Entries[0].GetAttributeValues("memberOf")) > 0 {
		for _, group := range sr.Entries[0].GetAttributeValues("memberOf") {
			if group == l.GetAdminGroup() {
				admin = true
			}
			short := l.DNToGroupname(group)
			if short != "" {
				groups = append(groups, short)
			}
		}
	}

	return &LDAPUser{
		DN:         sr.Entries[0].DN,
		Username:   username,
		FirstName:  sr.Entries[0].GetAttributeValue("givenName"),
		LastName:   sr.Entries[0].GetAttributeValue("sn"),
		Email:      sr.Entries[0].GetAttributeValue("mail"),
		LockedTime: sr.Entries[0].GetAttributeValue("pwdAccountLockedTime"),
		IsActive:   active,
		IsAdmin:    admin,
		Groups:     groups,
	}, nil
}

func (l LDAP) GetGroup(groupname string) (*LDAPGroup, error) {
	c, err := l.Setup(true)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer c.Close()

	search := ldap.NewSearchRequest(
		l.GetGroupDN(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(cn=%s)", groupname),
		[]string{"cn", "description", "member", "owner"},
		nil)

	sr, err := c.Search(search)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if len(sr.Entries) != 1 {
		return nil, errors.Errorf("No such group %s", groupname)
	}

	owners := make([]string, 0)
	members := make([]string, 0)

	for _, owner := range sr.Entries[0].GetAttributeValues("owner") {
		owners = append(owners, l.DNToUsername(owner))
	}

	for _, member := range sr.Entries[0].GetAttributeValues("member") {
		members = append(members, l.DNToUsername(member))
	}

	return &LDAPGroup{
		DN:        sr.Entries[0].DN,
		Groupname: groupname,
		Name:      sr.Entries[0].GetAttributeValue("description"),
		Owners:    owners,
		Members:   members,
	}, nil
}

func (l LDAP) CreateUser(user *LDAPUser, password string, creds *LDAPCredentials) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	hasher := sha1.New()
	hasher.Write([]byte(password))
	shaPass := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	ar := ldap.NewAddRequest(user.DN)
	ar.Attribute("objectClass", []string{
		"inetOrgPerson",
		"person",
		"organizationalPerson",
		"top",
	})
	ar.Attribute("uid", []string{user.Username})
	ar.Attribute("givenName", []string{user.FirstName})
	ar.Attribute("sn", []string{user.LastName})
	ar.Attribute("cn", []string{user.FirstName + " " + user.LastName})
	ar.Attribute("displayName", []string{user.FirstName + " " + user.LastName})
	ar.Attribute("mail", []string{user.Email})
	ar.Attribute("userPassword", []string{"{SHA}" + shaPass})
	err = c.Add(ar)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (l LDAP) EditUser(user *LDAPUser, creds *LDAPCredentials) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	mr := ldap.NewModifyRequest(user.DN)
	mr.Replace("mail", []string{user.Email})
	mr.Replace("givenName", []string{user.FirstName})
	mr.Replace("sn", []string{user.LastName})
	mr.Replace("cn", []string{user.FirstName + " " + user.LastName})
	mr.Replace("displayName", []string{user.FirstName + " " + user.LastName})
	err = c.Modify(mr)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (l LDAP) EnableUser(user *LDAPUser, creds *LDAPCredentials) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	mr := ldap.NewModifyRequest(user.DN)
	mr.Delete("pwdAccountLockedTime", []string{})
	err = c.Modify(mr)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (l LDAP) DisableUser(user *LDAPUser, creds *LDAPCredentials, reason string) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	mr := ldap.NewModifyRequest(user.DN)
	mr.Add("pwdAccountLockedTime", []string{ADMIN_LOCKED_TIME})
	if reason != "" {
		mr.Add("description", []string{reason})
	}
	err = c.Modify(mr)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (l LDAP) IsMember(groupname, username string) (bool, error) {
	c, err := l.Setup(true)
	if err != nil {
		return false, errors.Trace(err)
	}
	defer c.Close()

	search := ldap.NewSearchRequest(
		l.GetGroupDN(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(cn=%s)(member=uid=%s,%s)", groupname, username, l.GetUserDN()),
		[]string{"cn"},
		nil)

	sr, err := c.Search(search)
	if err != nil {
		return false, errors.Trace(err)
	}

	if len(sr.Entries) != 1 {
		return false, nil
	}

	return true, nil
}

func (l LDAP) CreateGroup(group *LDAPGroup, creds *LDAPCredentials) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	ar := ldap.NewAddRequest(group.DN)
	ar.Attribute("objectClass", []string{
		"groupOfNames",
		"top",
	})
	ar.Attribute("cn", []string{group.Groupname})
	ar.Attribute("description", []string{group.Name})
	ar.Attribute("member", group.Members)
	if len(group.Owners) > 0 {
		ar.Attribute("owner", group.Owners)
	}
	err = c.Add(ar)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (l LDAP) EditGroup(group *LDAPGroup, creds *LDAPCredentials) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	mr := ldap.NewModifyRequest(group.DN)
	mr.Replace("description", []string{group.Name})
	err = c.Modify(mr)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (l LDAP) AddMember(group *LDAPGroup, user *LDAPUser, creds *LDAPCredentials) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	mr := ldap.NewModifyRequest(group.DN)
	mr.Add("member", []string{user.DN})
	err = c.Modify(mr)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (l LDAP) RemoveMember(group *LDAPGroup, user *LDAPUser, creds *LDAPCredentials) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	mr := ldap.NewModifyRequest(group.DN)
	mr.Delete("member", []string{user.DN})
	err = c.Modify(mr)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (l LDAP) AddOwner(group *LDAPGroup, user *LDAPUser, creds *LDAPCredentials) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	mr := ldap.NewModifyRequest(group.DN)
	mr.Add("owner", []string{user.DN})
	err = c.Modify(mr)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (l LDAP) RemoveOwner(group *LDAPGroup, user *LDAPUser, creds *LDAPCredentials) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(creds.DN, creds.Password)
	if err != nil {
		return errors.Trace(err)
	}

	mr := ldap.NewModifyRequest(group.DN)
	mr.Delete("owner", []string{user.DN})
	err = c.Modify(mr)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (l LDAP) SetPassword(user *LDAPUser, oldPass, newPass string) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(user.DN, oldPass)
	if err != nil {
		return errors.Trace(err)
	}

	pmr := ldap.NewPasswordModifyRequest("", oldPass, newPass)
	_, err = c.PasswordModify(pmr)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (l LDAP) SetForgotPassword(user *LDAPUser, newPass string) error {
	c, err := l.Setup(false)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	err = c.Bind(l.GetForgotUsername(), l.GetForgotPassword())
	if err != nil {
		return errors.Trace(err)
	}

	pmr := ldap.NewPasswordModifyRequest(user.DN, "", newPass)
	_, err = c.PasswordModify(pmr)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (l LDAP) SynchronizeAll(r SyncReceiver) error {
	c, err := l.Setup(true)
	if err != nil {
		return errors.Trace(err)
	}
	defer c.Close()

	userSearch := ldap.NewSearchRequest(
		l.GetUserDN(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(uid=*)",
		[]string{"uid", "mail", "givenName", "sn", "pwdAccountLockedTime", "memberOf"},
		nil)

	groupSearch := ldap.NewSearchRequest(
		l.GetGroupDN(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(cn=*)",
		[]string{"cn", "description", "member", "owner"},
		nil)

	// Users
	usr, err := c.SearchWithPaging(userSearch, 200)
	if err != nil {
		return errors.Trace(err)
	}

	for _, entry := range usr.Entries {
		active := true
		if entry.GetAttributeValue("pwdAccountLockedTime") != "" {
			active = false
		}
		groups := make([]string, len(entry.GetAttributeValues("memberOf")))
		admin := false
		if len(entry.GetAttributeValues("memberOf")) > 0 {
			for _, group := range entry.GetAttributeValues("memberOf") {
				if group == l.GetAdminGroup() {
					admin = true
				}
				short := l.DNToGroupname(group)
				if short != "" {
					groups = append(groups, short)
				}
			}
		}
		user := &LDAPUser{
			DN:         entry.DN,
			Username:   entry.GetAttributeValue("uid"),
			FirstName:  entry.GetAttributeValue("givenName"),
			LastName:   entry.GetAttributeValue("sn"),
			Email:      entry.GetAttributeValue("mail"),
			LockedTime: entry.GetAttributeValue("pwdAccountLockedTime"),
			IsActive:   active,
			IsAdmin:    admin,
			Groups:     groups,
		}
		err = r.OnUser(user)
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Groups
	gsr, err := c.SearchWithPaging(groupSearch, 200)
	if err != nil {
		return errors.Trace(err)
	}

	for _, entry := range gsr.Entries {
		owners := make([]string, 0)
		members := make([]string, 0)
		for _, owner := range entry.GetAttributeValues("owner") {
			owners = append(owners, l.DNToUsername(owner))
		}
		for _, member := range entry.GetAttributeValues("member") {
			members = append(members, l.DNToUsername(member))
		}
		group := &LDAPGroup{
			DN:        entry.DN,
			Groupname: entry.GetAttributeValue("cn"),
			Name:      entry.GetAttributeValue("description"),
			Owners:    owners,
			Members:   members,
		}
		err = r.OnGroup(group)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func Authenticate(ls []LDAPConfiguration, user, pass string) (bool, error) {
	var err error
	var success bool
	for _, l := range ls {
		success, err = l.Auth(user, pass)
		if err != nil {
			continue
		}
		return success, nil
	}
	return false, errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func GetUser(ls []LDAPConfiguration, username string) (*LDAPUser, error) {
	var err error
	var user *LDAPUser
	for _, l := range ls {
		user, err = l.GetUser(username)
		if err != nil {
			continue
		}
		return user, nil
	}
	return nil, errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func GetGroup(ls []LDAPConfiguration, groupname string) (*LDAPGroup, error) {
	var err error
	var group *LDAPGroup
	for _, l := range ls {
		group, err = l.GetGroup(groupname)
		if err != nil {
			continue
		}
		return group, nil
	}
	return nil, errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func CreateUser(ls []LDAPConfiguration, user *LDAPUser, password string, creds *LDAPCredentials) error {
	var err error
	for _, l := range ls {
		err = l.CreateUser(user, password, creds)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func EditUser(ls []LDAPConfiguration, user *LDAPUser, creds *LDAPCredentials) error {
	var err error
	for _, l := range ls {
		err = l.EditUser(user, creds)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func EnableUser(ls []LDAPConfiguration, user *LDAPUser, creds *LDAPCredentials) error {
	var err error
	for _, l := range ls {
		err = l.EnableUser(user, creds)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func DisableUser(ls []LDAPConfiguration, user *LDAPUser, creds *LDAPCredentials, reason string) error {
	var err error
	for _, l := range ls {
		err = l.DisableUser(user, creds, reason)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func IsMember(ls []LDAPConfiguration, groupname, username string) (bool, error) {
	var err error
	var is_member bool
	for _, l := range ls {
		is_member, err = l.IsMember(groupname, username)
		if err != nil {
			continue
		}
		return is_member, nil
	}
	return false, errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func CreateGroup(ls []LDAPConfiguration, group *LDAPGroup, creds *LDAPCredentials) error {
	var err error
	for _, l := range ls {
		err = l.CreateGroup(group, creds)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func EditGroup(ls []LDAPConfiguration, group *LDAPGroup, creds *LDAPCredentials) error {
	var err error
	for _, l := range ls {
		err = l.EditGroup(group, creds)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func AddMember(ls []LDAPConfiguration, group *LDAPGroup, user *LDAPUser, creds *LDAPCredentials) error {
	var err error
	for _, l := range ls {
		err = l.AddMember(group, user, creds)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func RemoveMember(ls []LDAPConfiguration, group *LDAPGroup, user *LDAPUser, creds *LDAPCredentials) error {
	var err error
	for _, l := range ls {
		err = l.RemoveMember(group, user, creds)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func AddOwner(ls []LDAPConfiguration, group *LDAPGroup, user *LDAPUser, creds *LDAPCredentials) error {
	var err error
	for _, l := range ls {
		err = l.AddOwner(group, user, creds)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func RemoveOwner(ls []LDAPConfiguration, group *LDAPGroup, user *LDAPUser, creds *LDAPCredentials) error {
	var err error
	for _, l := range ls {
		err = l.RemoveOwner(group, user, creds)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func SetPassword(ls []LDAPConfiguration, user *LDAPUser, oldPass, newPass string) error {
	var err error
	for _, l := range ls {
		err = l.SetPassword(user, oldPass, newPass)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func SetForgotPassword(ls []LDAPConfiguration, user *LDAPUser, newPass string) error {
	var err error
	for _, l := range ls {
		err = l.SetForgotPassword(user, newPass)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.Annotatef(err, "Operation failed on all LDAP servers")
}

func SynchronizeAll(ls []LDAPConfiguration, r SyncReceiver, c chan error) {
	var err error
	for _, l := range ls {
		err = l.SynchronizeAll(r)
		if err != nil {
			c <- err
			continue
		}
		return
	}
	c <- errors.Annotatef(err, "Operation failed on all LDAP servers")
	return
}
