# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in go
**Pair ID:** 4281_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4281_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```go
Lines 1-33 of the vulnerable file.

package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
	"github.com/gophish/gophish/util"
	"github.com/jordan-wright/email"
)

type cloneRequest struct {
	URL              string `json:"url"`
	IncludeResources bool   `json:"include_resources"`
}

func (cr *cloneRequest) validate() error {
	if cr.URL == "" {
		return errors.New("No URL Specified")
	}
	return nil
}

type cloneResponse struct {
	HTML string `json:"html"`
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,7 @@
 	"strings"
 
 	"github.com/PuerkitoBio/goquery"
+	"github.com/gophish/gophish/dialer"
 	log "github.com/gophish/gophish/logger"
 	"github.com/gophish/gophish/models"
 	"github.com/gophish/gophish/util"
@@ -113,7 +114,9 @@
 		JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
 		return
 	}
+	restrictedDialer := dialer.Dialer()
 	tr := &http.Transport{
+		DialContext: restrictedDialer.DialContext,
 		TLSClientConfig: &tls.Config{
 			InsecureSkipVerify: true,
 		},
```
