# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in go
**Pair ID:** 4281_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4281_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```go
Lines 1-36 of the vulnerable file.

package config

import (
	"encoding/json"
	"io/ioutil"

	log "github.com/gophish/gophish/logger"
)

// AdminServer represents the Admin server configuration details
type AdminServer struct {
	ListenURL string `json:"listen_url"`
	UseTLS    bool   `json:"use_tls"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
	CSRFKey   string `json:"csrf_key"`
}

// PhishServer represents the Phish server configuration details
type PhishServer struct {
	ListenURL string `json:"listen_url"`
	UseTLS    bool   `json:"use_tls"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
}

// Config represents the configuration information.
type Config struct {
	AdminConf      AdminServer `json:"admin_server"`
	PhishConf      PhishServer `json:"phish_server"`
	DBName         string      `json:"db_name"`
	DBPath         string      `json:"db_path"`
	DBSSLCaPath    string      `json:"db_sslca_path"`
	MigrationsPath string      `json:"migrations_prefix"`
	TestFlag       bool        `json:"test_flag"`
	ContactAddress string      `json:"contact_address"`
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,11 +9,12 @@
 
 // AdminServer represents the Admin server configuration details
 type AdminServer struct {
-	ListenURL string `json:"listen_url"`
-	UseTLS    bool   `json:"use_tls"`
-	CertPath  string `json:"cert_path"`
-	KeyPath   string `json:"key_path"`
-	CSRFKey   string `json:"csrf_key"`
+	ListenURL            string   `json:"listen_url"`
+	UseTLS               bool     `json:"use_tls"`
+	CertPath             string   `json:"cert_path"`
+	KeyPath              string   `json:"key_path"`
+	CSRFKey              string   `json:"csrf_key"`
+	AllowedInternalHosts []string `json:"allowed_internal_hosts"`
 }
 
 // PhishServer represents the Phish server configuration details
```
