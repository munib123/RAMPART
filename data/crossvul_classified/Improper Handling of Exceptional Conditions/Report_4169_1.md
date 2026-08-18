# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in go
**Pair ID:** 4169_1
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4169_1`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```go
Lines 36-57 of the vulnerable file.

	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	rfcerr := ErrorToRFC6749Error(err)
	if !f.SendDebugMessagesToClients {
		rfcerr = rfcerr.Sanitize()
	}

	js, err := json.Marshal(rfcerr)
	if err != nil {
		if f.SendDebugMessagesToClients {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}
		return
	}

	rw.WriteHeader(rfcerr.Code)
	rw.Write(js)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,5 +53,6 @@
 	}
 
 	rw.WriteHeader(rfcerr.Code)
-	rw.Write(js)
+	// ignoring the error because the connection is broken when it happens
+	_, _ = rw.Write(js)
 }
```
