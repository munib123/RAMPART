# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in go
**Pair ID:** 4536_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4536_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```go
Lines 541-581 of the vulnerable file.

// or matches /^:\d*$/
// *** taken from net/url, modified to accept ":*"
func validOptionalPort(port string) bool {
	if port == "" || port == ":*" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// IsValidRedirect checks whether the redirect URL is whitelisted
func (p *OAuthProxy) IsValidRedirect(redirect string) bool {
	switch {
	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//"):
		return true
	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
		redirectURL, err := url.Parse(redirect)
		if err != nil {
			return false
		}
		redirectHostname := redirectURL.Hostname()

		for _, domain := range p.whitelistDomains {
			domainHostname, domainPort := splitHostPort(strings.TrimLeft(domain, "."))
			if domainHostname == "" {
				continue
			}

			if (redirectHostname == domainHostname) || (strings.HasPrefix(domain, ".") && strings.HasSuffix(redirectHostname, domainHostname)) {
				// the domain names match, now validate the ports
				// if the whitelisted domain's port is '*', allow all ports
				// if the whitelisted domain contains a specific port, only allow that port
				// if the whitelisted domain doesn't contain a port at all, only allow empty redirect ports ie http and https
				redirectPort := redirectURL.Port()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -558,7 +558,7 @@
 // IsValidRedirect checks whether the redirect URL is whitelisted
 func (p *OAuthProxy) IsValidRedirect(redirect string) bool {
 	switch {
-	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//"):
+	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") && !strings.HasPrefix(redirect, "/\\"):
 		return true
 	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
 		redirectURL, err := url.Parse(redirect)
```
