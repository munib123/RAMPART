# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in go
**Pair ID:** 4169_3
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4169_3`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```go
Lines 36-76 of the vulnerable file.

	rfcerr := ErrorToRFC6749Error(err)
	if !f.SendDebugMessagesToClients {
		rfcerr = rfcerr.Sanitize()
	}

	if !ar.IsRedirectURIValid() {
		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

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
		return
	}

	redirectURI := ar.GetRedirectURI()

	// The endpoint URI MUST NOT include a fragment component.
	redirectURI.Fragment = ""

	query := rfcerr.ToValues()
	query.Add("state", ar.GetState())

	var redirectURIString string
	if !(len(ar.GetResponseTypes()) == 0 || ar.GetResponseTypes().ExactOne("code")) && !errors.Is(err, ErrUnsupportedResponseType) {
		redirectURIString = redirectURI.String() + "#" + query.Encode()
	} else {
		for key, values := range redirectURI.Query() {
			for _, value := range values {
				query.Add(key, value)
			}
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,7 @@
 		}
 
 		rw.WriteHeader(rfcerr.Code)
-		rw.Write(js)
+		_, _ = rw.Write(js)
 		return
 	}
 
```
