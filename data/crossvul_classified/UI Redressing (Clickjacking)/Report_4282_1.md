# CrossVul Fix Pair: Improper Restriction of Rendered UI Layers or Frames in go
**Pair ID:** 4282_1
**Vulnerability Class:** UI Redressing (Clickjacking)
**CWE:** CWE-1021
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4282_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Rendered UI Layers or Frames - A web application is expected to place restrictions on whether it is allowed to be rendered within frames, iframes, objects, embed or applet elements.

## Vulnerable Code
```go
Lines 159-186 of the vulnerable file.

// before executing the handler. If the request is unauthorized, a JSONError
// is returned.
func RequirePermission(perm string) func(http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := ctx.Get(r, "user").(models.User)
			access, err := user.HasPermission(perm)
			if err != nil {
				JSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !access {
				JSONError(w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
				return
			}
			next.ServeHTTP(w, r)
		}
	}
}

// JSONError returns an error in JSON format with the given
// status code and message
func JSONError(w http.ResponseWriter, c int, m string) {
	cj, _ := json.MarshalIndent(models.Response{Success: false, Message: m}, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", cj)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,6 +176,17 @@
 	}
 }
 
+// ApplySecurityHeaders applies various security headers according to best-
+// practices.
+func ApplySecurityHeaders(next http.Handler) http.HandlerFunc {
+	return func(w http.ResponseWriter, r *http.Request) {
+		csp := "frame-ancestors 'none';"
+		w.Header().Set("Content-Security-Policy", csp)
+		w.Header().Set("X-Frame-Options", "DENY")
+		next.ServeHTTP(w, r)
+	}
+}
+
 // JSONError returns an error in JSON format with the given
 // status code and message
 func JSONError(w http.ResponseWriter, c int, m string) {
```
