# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in go
**Pair ID:** 120_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `120_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```go
Lines 10-57 of the vulnerable file.

// Middleware generates a middleware wrapper for request hanlders.
// Responds with 401 for requests with missing/invalid/incomplete token with verified email address.
func authMiddleware(a *auth.Authenticator, hdlr http.HandlerFunc) http.Handler {
	f := func(user *auth.User, w http.ResponseWriter, r *http.Request) {
		hdlr.ServeHTTP(w, r)
	}
	return authMiddlewareWithUser(a, f)
}

func authMiddlewareWithUser(a *auth.Authenticator, handlerFunc func(user *auth.User, w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.Authenticate(r)
		if err != nil {
			plog.Infof("authentication failed: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.Token))

		safe := false
		switch r.Method {
		case
			"GET",
			"HEAD",
			"OPTIONS",
			"TRACE":
			safe = true
		}

		if !safe {
			if err := a.VerifyReferer(r); err != nil {
				plog.Infof("Invalid referer %v", err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if err := a.VerifyCSRFToken(r); err != nil {
				plog.Infof("Invalid CSRFToken %v", err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		handlerFunc(user, w, r)
	})
}

func securityHeadersMiddleware(hdlr http.Handler) http.HandlerFunc {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,27 +27,16 @@
 
 		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.Token))
 
-		safe := false
-		switch r.Method {
-		case
-			"GET",
-			"HEAD",
-			"OPTIONS",
-			"TRACE":
-			safe = true
+		if err := a.VerifySourceOrigin(r); err != nil {
+			plog.Infof("invalid source origin: %v", err)
+			w.WriteHeader(http.StatusForbidden)
+			return
 		}
 
-		if !safe {
-			if err := a.VerifyReferer(r); err != nil {
-				plog.Infof("Invalid referer %v", err)
-				w.WriteHeader(http.StatusForbidden)
-				return
-			}
-			if err := a.VerifyCSRFToken(r); err != nil {
-				plog.Infof("Invalid CSRFToken %v", err)
-				w.WriteHeader(http.StatusForbidden)
-				return
-			}
+		if err := a.VerifyCSRFToken(r); err != nil {
+			plog.Infof("invalid CSRFToken: %v", err)
+			w.WriteHeader(http.StatusForbidden)
+			return
 		}
 
 		handlerFunc(user, w, r)
```
