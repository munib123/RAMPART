# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in go
**Pair ID:** 1928_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1928_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```go
Lines 420-462 of the vulnerable file.

func (p *OAuthProxy) SaveSession(rw http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) error {
	return p.sessionStore.Save(rw, req, s)
}

// IsValidRedirect checks whether the redirect URL is whitelisted
func (p *OAuthProxy) IsValidRedirect(redirect string) bool {
	switch {
	case redirect == "":
		// The user didn't specify a redirect, should fallback to `/`
		return false
	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") && !invalidRedirectRegex.MatchString(redirect):
		return true
	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
		redirectURL, err := url.Parse(redirect)
		if err != nil {
			logger.Printf("Rejecting invalid redirect %q: scheme unsupported or missing", redirect)
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
				if (domainPort == "*") ||
					(domainPort == redirectPort) ||
					(domainPort == "" && redirectPort == "") {
					return true
				}
			}
		}

		logger.Printf("Rejecting invalid redirect %q: domain / port not in whitelist", redirect)
		return false
	default:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -437,21 +437,23 @@
 		}
 		redirectHostname := redirectURL.Hostname()
 
-		for _, domain := range p.whitelistDomains {
-			domainHostname, domainPort := splitHostPort(strings.TrimLeft(domain, "."))
-			if domainHostname == "" {
+		for _, allowedDomain := range p.whitelistDomains {
+			allowedHost, allowedPort := splitHostPort(allowedDomain)
+			if allowedHost == "" {
 				continue
 			}
 
-			if (redirectHostname == domainHostname) || (strings.HasPrefix(domain, ".") && strings.HasSuffix(redirectHostname, domainHostname)) {
+			if redirectHostname == strings.TrimPrefix(allowedHost, ".") ||
+				(strings.HasPrefix(allowedHost, ".") &&
+					strings.HasSuffix(redirectHostname, allowedHost)) {
 				// the domain names match, now validate the ports
 				// if the whitelisted domain's port is '*', allow all ports
 				// if the whitelisted domain contains a specific port, only allow that port
 				// if the whitelisted domain doesn't contain a port at all, only allow empty redirect ports ie http and https
 				redirectPort := redirectURL.Port()
-				if (domainPort == "*") ||
-					(domainPort == redirectPort) ||
-					(domainPort == "" && redirectPort == "") {
+				if allowedPort == "*" ||
+					allowedPort == redirectPort ||
+					(allowedPort == "" && redirectPort == "") {
 					return true
 				}
 			}
```
