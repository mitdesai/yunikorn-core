/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package security

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/go-ldap/ldap/v3"

	"github.com/apache/yunikorn-core/pkg/common"
)

// mock ldapConn_Bind for testing LDAPLookupGroupIds
func mockLDAPConn_Bind(username string) (*ldap.SearchResult, error) {
	return &ldap.SearchResult{
		Entries: []*ldap.Entry{
			{
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "memberOf",
						Values: []string{"CN=group1,OU=groups,DC=example,DC=com", "CN=group2,OU=groups,DC=example,DC=com"},
					},
				},
			},
		},
	}, nil
}

func TestLdapLookupUser(t *testing.T) {
	u, err := LdapLookupUser("testuser")
	assert.NilError(t, err)
	assert.Assert(t, "testuser" == u.Username)
	assert.Assert(t, "testuser" == u.Gid)
	assert.Assert(t, "1211" == u.Uid)
}

func TestLdapLookupGroupID(t *testing.T) {
	g, err := LdapLookupGroupID("testgroup")
	assert.NilError(t, err)
	assert.Equal(t, "testgroup", g.Gid)
	assert.Equal(t, "testgroup", g.Name)
}

func TestLDAPLookupGroupIds(t *testing.T) {
	origLDAPConn_Bind := LDAPConn_Bind
	LDAPConn_Bind = mockLDAPConn_Bind
	defer func() { LDAPConn_Bind = origLDAPConn_Bind }()

	u := &user.User{Username: "testuser"}
	groups, err := LDAPLookupGroupIds(u)
	assert.NilError(t, err)
	assert.Assert(t, strings.Contains(strings.Join(groups, ","), "group1"))
	assert.Assert(t, strings.Contains(strings.Join(groups, ","), "group2"))
}

func TestLDAPLookupGroupIds_Error(t *testing.T) {
	origLDAPConn_Bind := LDAPConn_Bind
	LDAPConn_Bind = func(username string) (*ldap.SearchResult, error) {
		return nil, errors.New("ldap error")
	}
	defer func() { LDAPConn_Bind = origLDAPConn_Bind }()

	u := &user.User{Username: "testuser"}
	groups, err := LDAPLookupGroupIds(u)
	assert.Error(t, err, "ldap error")
	assert.Assert(t, groups == nil)
}

func TestLDAPConn_Bind_Error(t *testing.T) {
	origLDAPConn_Bind := LDAPConn_Bind
	LDAPConn_Bind = func(userName string) (*ldap.SearchResult, error) {
		return nil, errors.New("ldap bind error")
	}
	defer func() { LDAPConn_Bind = origLDAPConn_Bind }()

	_, err := LDAPConn_Bind("testuser")
	assert.Error(t, err, "ldap bind error")
}

func TestReadSecrets_SkipsK8sMetadataAndDirs(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.Mkdir(filepath.Join(tmpDir, "..data"), 0755)
	if err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	err = os.Mkdir(filepath.Join(tmpDir, "dir1"), 0755)
	if err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "key1"), []byte("value1"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "..timestamp"), []byte("meta"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	origLdapMountPath := common.LdapMountPath
	common.LdapMountPath = tmpDir
	defer func() { common.LdapMountPath = origLdapMountPath }()

	readSecrets()
	// Should log unknown key, but not panic

	// Assert that ldap conf is set to default values
	assert.Assert(t, common.DefaultLdapHost == ldapConf.Host, "DefaultLdapHost should be equal to ldapConf.Host")
	assert.Assert(t, common.DefaultLdapPort == ldapConf.Port, "DefaultLdapPort should be equal to ldapConf.Port")
	assert.Assert(t, common.DefaultLdapBaseDN == ldapConf.BaseDN, "DefaultLdapBaseDN should be equal to ldapConf.BaseDN")
	assert.Assert(t, common.DefaultLdapFilter == ldapConf.Filter, "DefaultLdapFilter should be equal to ldapConf.Filter")
	assert.Assert(t, common.DefaultLdapGroupAttr == ldapConf.GroupAttr, "DefaultLdapGroupAttr should be equal to ldapConf.GroupAttr")
	assert.Assert(t, strings.Join(common.DefaultLdapReturnAttr, ",") == strings.Join(ldapConf.ReturnAttr, ","), "DefaultLdapReturnAttr should be equal to ldapConf.ReturnAttr")
	assert.Assert(t, common.DefaultLdapBindUser == ldapConf.BindUser, "DefaultLdapBindUser should be equal to ldapConf.BindUser")
	assert.Assert(t, common.DefaultLdapBindPassword == ldapConf.BindPassword, "DefaultLdapBindPassword should be equal to ldapConf.BindPassword")
	assert.Assert(t, common.DefaultLdapInsecure == ldapConf.Insecure, "DefaultLdapInsecure should be equal to ldapConf.Insecure")
	assert.Assert(t, common.DefaultLdapSSL == ldapConf.SSL, "DefaultLdapSSL should be equal to ldapConf.SSL")
}

func TestReadSecrets_HandlesMissingSecretsDir(t *testing.T) {
	origLdapMountPath := common.LdapMountPath
	common.LdapMountPath = "/nonexistent"
	defer func() { common.LdapMountPath = origLdapMountPath }()

	readSecrets()

	// Assert that ldap conf is set to default values
	assert.Equal(t, common.DefaultLdapHost, ldapConf.Host)
	assert.Equal(t, common.DefaultLdapPort, ldapConf.Port)
	assert.Equal(t, common.DefaultLdapBaseDN, ldapConf.BaseDN)
	assert.Equal(t, common.DefaultLdapFilter, ldapConf.Filter)
	assert.Equal(t, common.DefaultLdapGroupAttr, ldapConf.GroupAttr)
	assert.Assert(t, strings.Join(common.DefaultLdapReturnAttr, ",") == strings.Join(ldapConf.ReturnAttr, ","))
	assert.Assert(t, common.DefaultLdapBindUser == ldapConf.BindUser)
	assert.Assert(t, common.DefaultLdapBindPassword == ldapConf.BindPassword)
	assert.Assert(t, common.DefaultLdapInsecure == ldapConf.Insecure)
	assert.Assert(t, common.DefaultLdapSSL == ldapConf.SSL)
}

func TestReadSecrets_HandlesUnknownKey(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "unknownKey"), []byte("somevalue"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	origLdapMountPath := common.LdapMountPath
	common.LdapMountPath = tmpDir
	defer func() { common.LdapMountPath = origLdapMountPath }()

	readSecrets()
	// Should log unknown key, but not panic

	// Assert that ldap conf is set to default values
	assert.Equal(t, common.DefaultLdapHost, ldapConf.Host)
	assert.Equal(t, common.DefaultLdapPort, ldapConf.Port)
	assert.Equal(t, common.DefaultLdapBaseDN, ldapConf.BaseDN)
	assert.Equal(t, common.DefaultLdapFilter, ldapConf.Filter)
	assert.Equal(t, common.DefaultLdapGroupAttr, ldapConf.GroupAttr)
	assert.Assert(t, strings.Join(common.DefaultLdapReturnAttr, ",") == strings.Join(ldapConf.ReturnAttr, ","))
	assert.Assert(t, common.DefaultLdapBindUser == ldapConf.BindUser)
	assert.Assert(t, common.DefaultLdapBindPassword == ldapConf.BindPassword)
	assert.Assert(t, common.DefaultLdapInsecure == ldapConf.Insecure)
	assert.Assert(t, common.DefaultLdapSSL == ldapConf.SSL)
}

func TestReadSecrets_HandlesInvalidPortAndBool(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, common.LdapPort), []byte("notanint"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapInsecure), []byte("notabool"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapSSL), []byte("notabool"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	origLdapMountPath := common.LdapMountPath
	common.LdapMountPath = tmpDir
	defer func() { common.LdapMountPath = origLdapMountPath }()

	readSecrets()
	// Should not panic on invalid values

	// Assert that ldapConf.Port is set to DefaultLdapPort when invalid int value is provided
	assert.Equal(t, common.DefaultLdapPort, ldapConf.Port)

	// Assert that rest of ldap conf is set to default values
	assert.Equal(t, common.DefaultLdapHost, ldapConf.Host)
	assert.Equal(t, common.DefaultLdapBaseDN, ldapConf.BaseDN)
	assert.Equal(t, common.DefaultLdapFilter, ldapConf.Filter)
	assert.Equal(t, common.DefaultLdapGroupAttr, ldapConf.GroupAttr)
	assert.Assert(t, strings.Join(common.DefaultLdapReturnAttr, ",") == strings.Join(ldapConf.ReturnAttr, ","))
	assert.Assert(t, common.DefaultLdapBindUser == ldapConf.BindUser)
	assert.Assert(t, common.DefaultLdapBindPassword == ldapConf.BindPassword)
	assert.Assert(t, common.DefaultLdapInsecure == ldapConf.Insecure)
	assert.Assert(t, common.DefaultLdapSSL == ldapConf.SSL)
}

func TestReadSecrets_SetsValues(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, common.LdapHost), []byte("myhost"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapPort), []byte("1234"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapBaseDN), []byte("dc=test,dc=com"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapFilter), []byte("(&(uid=%s))"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapGroupAttr), []byte("groups"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapReturnAttr), []byte("memberOf,groups"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapBindUser), []byte("binduser"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapBindPassword), []byte("bindpass"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapInsecure), []byte("true"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, common.LdapSSL), []byte("true"), 0600)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	origLdapMountPath := common.LdapMountPath
	common.LdapMountPath = tmpDir
	defer func() { common.LdapMountPath = origLdapMountPath }()

	readSecrets()
	assert.Equal(t, "myhost", ldapConf.Host)
	portStr := "1234"
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to convert port to integer: %v", err)
	}
	assert.Equal(t, port, ldapConf.Port)
	assert.Equal(t, "dc=test,dc=com", ldapConf.BaseDN)
	assert.Equal(t, "(&(uid=%s))", ldapConf.Filter)
	assert.Equal(t, "groups", ldapConf.GroupAttr)
	assert.Equal(t, "memberOf,groups", strings.Join(ldapConf.ReturnAttr, ","))
	assert.Equal(t, "binduser", ldapConf.BindUser)
	assert.Equal(t, "bindpass", ldapConf.BindPassword)
	insecureStr := "true"
	insecure, err := strconv.ParseBool(insecureStr)
	if err != nil {
		t.Fatalf("failed to convert insecure to boolean: %v", err)
	}
	assert.Assert(t, insecure == ldapConf.Insecure)
	sslStr := "true"
	ssl, err := strconv.ParseBool(sslStr)
	if err != nil {
		t.Fatalf("failed to convert ssl to boolean: %v", err)
	}
	assert.Assert(t, ssl == ldapConf.SSL)
}

func TestGetUserGroupCacheLdap(t *testing.T) {
	cache := GetUserGroupCacheLdap()
	assert.Assert(t, cache != nil)
	assert.Assert(t, cache.ugs != nil)
	assert.Assert(t, cache.lookup != nil)
	assert.Assert(t, cache.lookupGroupID != nil)
	assert.Assert(t, cache.groupIds != nil)
}
