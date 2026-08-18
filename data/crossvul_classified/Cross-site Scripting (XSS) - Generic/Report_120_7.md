# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in go
**Pair ID:** 120_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `120_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```go
Lines 44-84 of the vulnerable file.

var (
	plog = capnslog.NewPackageLogger("github.com/openshift/console", "server")
)

type jsGlobals struct {
	ConsoleVersion       string `json:"consoleVersion"`
	AuthDisabled         bool   `json:"authDisabled"`
	KubectlClientID      string `json:"kubectlClientID"`
	BasePath             string `json:"basePath"`
	LoginURL             string `json:"loginURL"`
	LoginSuccessURL      string `json:"loginSuccessURL"`
	LoginErrorURL        string `json:"loginErrorURL"`
	LogoutURL            string `json:"logoutURL"`
	LogoutRedirect       string `json:"logoutRedirect"`
	KubeAPIServerURL     string `json:"kubeAPIServerURL"`
	PrometheusBaseURL    string `json:"prometheusBaseURL"`
	DeveloperConsoleURL  string `json:"developerConsoleURL"`
	Branding             string `json:"branding"`
	DocumentationBaseURL string `json:"documentationBaseURL"`
	ClusterName          string `json:"clusterName"`
	CSRFToken            string `json:"CSRFToken"`
	GoogleTagManagerID   string `json:"googleTagManagerID"`
	LoadTestFactor       int    `json:"loadTestFactor"`
}

type Server struct {
	K8sProxyConfig       *proxy.Config
	BaseURL              *url.URL
	LogoutRedirect       *url.URL
	PublicDir            string
	TectonicVersion      string
	TectonicCACertFile   string
	Auther               *auth.Authenticator
	StaticUser           *auth.User
	KubectlClientID      string
	ClusterName          string
	KubeAPIServerURL     string
	DeveloperConsoleURL  string
	DocumentationBaseURL *url.URL
	Branding             string
	GoogleTagManagerID   string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,7 +61,6 @@
 	Branding             string `json:"branding"`
 	DocumentationBaseURL string `json:"documentationBaseURL"`
 	ClusterName          string `json:"clusterName"`
-	CSRFToken            string `json:"CSRFToken"`
 	GoogleTagManagerID   string `json:"googleTagManagerID"`
 	LoadTestFactor       int    `json:"loadTestFactor"`
 }
```
