# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in go
**Pair ID:** 334_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `334_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```go
Lines 16-37 of the vulnerable file.

		Handler: http.FileServer(http.Dir(assetPublicPath)),
	}
	return h
}

func isHTML(acceptContent []string) bool {
	for _, accept := range acceptContent {
		if strings.Contains(accept, "text/html") {
			return true
		}
	}
	return false
}

func (handler *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isHTML(r.Header["Accept"]) {
		w.Header().Set("Cache-Control", "max-age=31536000")
	} else {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}
	handler.Handler.ServeHTTP(w, r)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,5 +33,9 @@
 	} else {
 		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
 	}
+
+	w.Header().Add("X-Frame-Options", "DENY")
+	w.Header().Add("X-XSS-Protection", "1; mode=block")
+	w.Header().Add("X-Content-Type-Options", "nosniff")
 	handler.Handler.ServeHTTP(w, r)
 }
```
