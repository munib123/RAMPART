# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in go
**Pair ID:** 4169_2
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4169_2`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```go
Lines 22-43 of the vulnerable file.

package fosite

import (
	"encoding/json"
	"net/http"
)

func (f *Fosite) WriteAccessResponse(rw http.ResponseWriter, requester AccessRequester, responder AccessResponder) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	js, err := json.Marshal(responder.ToMap())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

	rw.WriteHeader(http.StatusOK)
	rw.Write(js)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,5 +39,5 @@
 	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
 
 	rw.WriteHeader(http.StatusOK)
-	rw.Write(js)
+	_, _ = rw.Write(js)
 }
```
