# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in go
**Pair ID:** 120_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `120_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```go
Lines 10-50 of the vulnerable file.

	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/dex/api"
	oidc "github.com/coreos/go-oidc"
	"github.com/coreos/pkg/capnslog"
	"golang.org/x/oauth2"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	CSRFCookieName    = "csrf-token"
	CSRFHeader        = "X-CSRFToken"
	stateCookieName   = "state-token"
	errorOAuth        = "oauth_error"
	errorLoginState   = "login_state_error"
	errorCookie       = "cookie_error"
	errorInternal     = "internal_error"
	errorMissingCode  = "missing_code"
	errorMissingState = "missing_state"
	errorInvalidCode  = "invalid_code"
	errorInvalidState = "invalid_state"
)

var log = capnslog.NewPackageLogger("github.com/openshift/console", "auth")

type Authenticator struct {
	tokenVerifier func(string) (*loginState, error)

	oauth2Client *oauth2.Config

	client *http.Client

	errorURL      string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,7 @@
 const (
 	CSRFCookieName    = "csrf-token"
 	CSRFHeader        = "X-CSRFToken"
+	CSRFQueryParam    = "x-csrf-token"
 	stateCookieName   = "state-token"
 	errorOAuth        = "oauth_error"
 	errorLoginState   = "login_state_error"
@@ -356,13 +357,24 @@
 	w.WriteHeader(http.StatusSeeOther)
 }
 
-func (a *Authenticator) VerifyReferer(r *http.Request) (err error) {
-	referer := r.Referer()
-	if len(referer) == 0 {
-		return fmt.Errorf("No referer!")
-	}
-
-	u, err := url.Parse(referer)
+func (a *Authenticator) getSourceOrigin(r *http.Request) string {
+	origin := r.Header.Get("Origin")
+	if len(origin) != 0 {
+		return origin
+	}
+
+	return r.Referer()
+}
+
+// VerifySourceOrigin checks that the Origin request header, if present, matches the target origin. Otherwise, it checks the Referer request header.
+// https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Identifying_Source_Origin
+func (a *Authenticator) VerifySourceOrigin(r *http.Request) (err error) {
+	source := a.getSourceOrigin(r)
+	if len(source) == 0 {
+		return fmt.Errorf("no Origin or Referer header in request")
+	}
+
+	u, err := url.Parse(source)
 	if err != nil {
 		return err
 	}
@@ -370,10 +382,11 @@
 	isValid := a.refererURL.Hostname() == u.Hostname() &&
 		a.refererURL.Port() == u.Port() &&
 		a.refererURL.Scheme == u.Scheme &&
-		strings.HasPrefix(u.Path, a.refererURL.Path)
+		// The Origin header does not have a path
+		(u.Path == "" || strings.HasPrefix(u.Path, a.refererURL.Path))
 
 	if !isValid {
-		return fmt.Errorf("invalid referer: %v expected `%v`", referer, a.refererURL)
+		return fmt.Errorf("invalid Origin or Referer: %v expected `%v`", source, a.refererURL)
 	}
 	return nil
 }
@@ -392,6 +405,11 @@
 
 func (a *Authenticator) VerifyCSRFToken(r *http.Request) (err error) {
 	CSRFToken := r.Header.Get(CSRFHeader)
+	if CSRFToken == "" {
+		// Fallback to a query parameter, which is needed for websockets
+		CSRFToken = r.URL.Query().Get(CSRFQueryParam)
+	}
+
 	CRSCookie, err := r.Cookie(CSRFCookieName)
 	if err != nil {
 		return fmt.Errorf("No CSRF Cookie!")
```
