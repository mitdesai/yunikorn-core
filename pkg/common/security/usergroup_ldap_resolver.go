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
	"crypto/tls"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/go-ldap/ldap/v3"

	"github.com/apache/yunikorn-core/pkg/common"
	"github.com/apache/yunikorn-core/pkg/log"
)

// LDAPResolverConfig holds the configuration for the LDAP resolver
type LdapResolverConfig struct {
	Host         string
	Port         int
	BaseDN       string
	Filter       string
	GroupAttr    string
	ReturnAttr   []string
	BindUser     string
	BindPassword string
	Insecure     bool
	SSL          bool
}

// Default values for the LDAP resolver
var ldapConf = LdapResolverConfig{
	Host:         common.DefaultLdapHost,
	Port:         common.DefaultLdapPort,
	BaseDN:       common.DefaultLdapBaseDN,
	Filter:       common.DefaultLdapFilter,
	GroupAttr:    common.DefaultLdapGroupAttr,
	ReturnAttr:   common.DefaultLdapReturnAttr,
	BindUser:     common.DefaultLdapBindUser,
	BindPassword: common.DefaultLdapBindPassword,
	Insecure:     common.DefaultLdapInsecure,
	SSL:          common.DefaultLdapSSL,
}

// read secrets from the secrets directory
func readSecrets() {
	secretsDir := common.LdapMountPath

	// Read all files from secrets directory
	files, err := os.ReadDir(secretsDir)
	if err != nil {
		log.Log(log.Security).Error("Failed to read secrets directory",
			zap.Error(err))
		return
	}

	secretCount := 0
	// Iterate over all secret files in the secrets directory
	for _, file := range files {
		fileName := file.Name()

		// Skip non-secret entries such as Kubernetes internal metadata (e.g., symlinks like "..data" or directories like "..timestamp")
		if strings.HasPrefix(fileName, "..") || file.IsDir() {
			log.Log(log.Security).Info("Ignoring non-secret entry (Kubernetes metadata entry or directory)",
				zap.String("name", fileName))
			continue
		}

		secretCount++
		secretKey := fileName // use the cached fileName
		secretValueBytes, err := os.ReadFile(filepath.Join(secretsDir, secretKey))
		if err != nil {
			log.Log(log.Security).Warn("Could not read secret file",
				zap.String("file", secretKey),
				zap.Error(err))
			continue
		}
		secretValue := strings.TrimSpace(string(secretValueBytes))

		// log the secret key and value
		log.Log(log.Security).Debug("Loaded LDAP secret",
			zap.String("key", secretKey))

		switch secretKey {
		case common.LdapHost:
			ldapConf.Host = secretValue
		case common.LdapPort:
			ldapConf.Port, err = strconv.Atoi(secretValue)
			if err != nil {
				log.Log(log.Security).Warn("Failed to convert LDAP port to integer, using default port", zap.Error(err))
				ldapConf.Port = common.DefaultLdapPort
			}
		case common.LdapBaseDN:
			ldapConf.BaseDN = secretValue
		case common.LdapFilter:
			ldapConf.Filter = secretValue
		case common.LdapGroupAttr:
			ldapConf.GroupAttr = secretValue
		case common.LdapReturnAttr:
			ldapConf.ReturnAttr = strings.Split(secretValue, ",")
		case common.LdapBindUser:
			ldapConf.BindUser = secretValue
		case common.LdapBindPassword:
			ldapConf.BindPassword = secretValue
		case common.LdapInsecure:
			ldapConf.Insecure, err = strconv.ParseBool(secretValue)
			if err != nil {
				log.Log(log.Security).Warn("Failed to convert LDAP Insecure to boolean, using default value", zap.Error(err))
				ldapConf.Insecure = common.DefaultLdapInsecure
			}
		case common.LdapSSL:
			ldapConf.SSL, err = strconv.ParseBool(secretValue)
			if err != nil {
				log.Log(log.Security).Warn("Failed to convert LDAP SSL to boolean, using default value", zap.Error(err))
				ldapConf.SSL = common.DefaultLdapSSL
			}
		default:
			log.Log(log.Security).Warn("Encountered unrecognized LDAP secret key",
				zap.String("key", secretKey))
		}
	}
	log.Log(log.Security).Info("Finished loading LDAP secrets",
		zap.Int("numberOfSecretsLoaded", secretCount))
}

func GetUserGroupCacheLdap() *UserGroupCache {
	readSecrets()

	return &UserGroupCache{
		ugs:           map[string]*UserGroup{},
		interval:      cleanerInterval * time.Second,
		lookup:        LdapLookupUser,
		lookupGroupID: LdapLookupGroupID,
		groupIds:      LDAPLookupGroupIds,
	}
}

// Default linux behaviour: a user is member of the primary group with the same name
func LdapLookupUser(userName string) (*user.User, error) {
	return &user.User{
		Uid:      "1211",
		Gid:      userName,
		Username: userName,
	}, nil
}

func LdapLookupGroupID(gid string) (*user.Group, error) {
	group := user.Group{Gid: gid}
	group.Name = gid
	return &group, nil
}

func LDAPLookupGroupIds(osUser *user.User) ([]string, error) {
	sr, err := LDAPConn_Bind(osUser.Username)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, entry := range sr.Entries {
		a := entry.GetAttributeValues("memberOf")
		println(a)
		for i := range a {
			s := strings.Split(a[i], ",")
			newgroup := strings.Split(s[0], "CN=")

			groups = append(groups, newgroup[1])
		}
	}
	return groups, nil
}

var LDAPConn_Bind = func(userName string) (*ldap.SearchResult, error) {
	var LDAP_URI string
	if ldapConf.SSL {
		LDAP_URI = "ldaps"
	} else {
		LDAP_URI = "ldap"
	}

	ldapaddr := fmt.Sprintf("%s://%s:%d", LDAP_URI, ldapConf.Host, ldapConf.Port)

	l, err := ldap.DialURL(ldapaddr,
		ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: ldapConf.Insecure})) // #nosec G402
	if err != nil {
		return nil, err
	}
	defer l.Close()

	err = l.Bind(ldapConf.BindUser, ldapConf.BindPassword)
	if err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		ldapConf.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(ldapConf.Filter, userName),
		ldapConf.ReturnAttr,
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	return sr, nil
}
