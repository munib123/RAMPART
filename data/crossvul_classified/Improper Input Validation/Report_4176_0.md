# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4176_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4176_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 101-141 of the vulnerable file.

// Test a given redirect URI against a pool of URIs provided by a registered client.
// If the OAuth 2.0 Client has loopback URIs registered either an IPv4 URI http://127.0.0.1 or
// an IPv6 URI http://[::1] a client is allowed to request a dynamic port and the server MUST accept
// it as a valid redirection uri.
//
// https://tools.ietf.org/html/rfc8252#section-7.3
// Native apps that are able to open a port on the loopback network
// interface without needing special permissions (typically, those on
// desktop operating systems) can use the loopback interface to receive
// the OAuth redirect.
//
// Loopback redirect URIs use the "http" scheme and are constructed with
// the loopback IP literal and whatever port the client is listening on.
func isMatchingRedirectURI(uri string, haystack []string) bool {
	requested, err := url.Parse(uri)
	if err != nil {
		return false
	}

	for _, b := range haystack {
		if strings.ToLower(b) == strings.ToLower(uri) || isLoopbackURI(requested, b) {
			return true
		}
	}
	return false
}

func isLoopbackURI(requested *url.URL, registeredURI string) bool {
	registered, err := url.Parse(registeredURI)
	if err != nil {
		return false
	}

	if registered.Scheme != "http" || !isLoopbackAddress(registered.Host) {
		return false
	}

	if requested.Scheme == "http" && isLoopbackAddress(requested.Host) && registered.Path == requested.Path {
		return true
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -118,24 +118,34 @@
 	}
 
 	for _, b := range haystack {
-		if strings.ToLower(b) == strings.ToLower(uri) || isLoopbackURI(requested, b) {
+		if b == uri || isMatchingAsLoopback(requested, b) {
 			return true
 		}
 	}
 	return false
 }
 
-func isLoopbackURI(requested *url.URL, registeredURI string) bool {
+func isMatchingAsLoopback(requested *url.URL, registeredURI string) bool {
 	registered, err := url.Parse(registeredURI)
 	if err != nil {
 		return false
 	}
 
-	if registered.Scheme != "http" || !isLoopbackAddress(registered.Host) {
-		return false
-	}
-
-	if requested.Scheme == "http" && isLoopbackAddress(requested.Host) && registered.Path == requested.Path {
+	// Native apps that are able to open a port on the loopback network
+	// interface without needing special permissions (typically, those on
+	// desktop operating systems) can use the loopback interface to receive
+	// the OAuth redirect.
+	//
+	// Loopback redirect URIs use the "http" scheme and are constructed with
+	// the loopback IP literal and whatever port the client is listening on.
+	//
+	// Source: https://tools.ietf.org/html/rfc8252#section-7.3
+	if requested.Scheme == "http" &&
+		isLoopbackAddress(requested.Host) &&
+		registered.Hostname() == requested.Hostname() &&
+		// The port is skipped here - see codedoc above!
+		registered.Path == requested.Path &&
+		registered.RawQuery == requested.RawQuery {
 		return true
 	}
 
```
