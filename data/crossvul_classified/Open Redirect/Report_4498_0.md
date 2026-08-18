# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in go
**Pair ID:** 4498_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4498_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```go
Lines 46-86 of the vulnerable file.

var SignatureHeaders = []string{
	"Content-Length",
	"Content-Md5",
	"Content-Type",
	"Date",
	"Authorization",
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Preferred-User",
	"X-Forwarded-Access-Token",
	"Cookie",
	"Gap-Auth",
}

var (
	// ErrNeedsLogin means the user should be redirected to the login page
	ErrNeedsLogin = errors.New("redirect to login page")

	// Used to check final redirects are not susceptible to open redirects.
	// Matches //, /\ and both of these with whitespace in between (eg / / or / \).
	invalidRedirectRegex = regexp.MustCompile(`^/(\s|\v)?(/|\\)`)
)

// OAuthProxy is the main authentication proxy
type OAuthProxy struct {
	CookieSeed     string
	CookieName     string
	CSRFCookieName string
	CookieDomains  []string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieExpire   time.Duration
	CookieRefresh  time.Duration
	CookieSameSite string
	Validator      func(string) bool

	RobotsPath        string
	SignInPath        string
	SignOutPath       string
	OAuthStartPath    string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,7 +63,7 @@
 
 	// Used to check final redirects are not susceptible to open redirects.
 	// Matches //, /\ and both of these with whitespace in between (eg / / or / \).
-	invalidRedirectRegex = regexp.MustCompile(`^/(\s|\v)?(/|\\)`)
+	invalidRedirectRegex = regexp.MustCompile(`[/\\](?:[\s\v]*|\.{1,2})[/\\]`)
 )
 
 // OAuthProxy is the main authentication proxy
```
