# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in go
**Pair ID:** 120_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `120_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```go
Lines 68-108 of the vulnerable file.

	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// decodeSubprotocol decodes the impersonation "headers" on a websocket.
// Subprotocols don't allow '=' or '/'
func decodeSubprotocol(encodedProtocol string) (string, error) {
	encodedProtocol = strings.Replace(encodedProtocol, "_", "=", -1)
	encodedProtocol = strings.Replace(encodedProtocol, "-", "/", -1)
	decodedProtocol, err := base64.StdEncoding.DecodeString(encodedProtocol)
	return string(decodedProtocol), err
}

var headerBlacklist = []string{"Cookie"}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isWebsocket := false
	upgrades := r.Header["Upgrade"]

	for _, upgrade := range upgrades {
		if strings.ToLower(upgrade) == "websocket" {
			isWebsocket = true
			break
		}
	}

	for _, h := range headerBlacklist {
		r.Header.Del(h)
	}

	if !isWebsocket {
		p.reverseProxy.ServeHTTP(w, r)
		return
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,9 +85,12 @@
 	return string(decodedProtocol), err
 }
 
-var headerBlacklist = []string{"Cookie"}
+var headerBlacklist = []string{"Cookie", "X-CSRFToken"}
 
 func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
+	// Block scripts from running in proxied content for browsers that support Content-Security-Policy.
+	w.Header().Set("Content-Security-Policy", "default-src 'none';")
+
 	isWebsocket := false
 	upgrades := r.Header["Upgrade"]
 
```
