# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in go
**Pair ID:** 4104_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4104_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```go
Lines 1-25 of the vulnerable file.

package api

import (
	"net/http"

	"github.com/containous/traefik/v2/pkg/log"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/gorilla/mux"
)

// DashboardHandler expose dashboard routes.
type DashboardHandler struct {
	Assets *assetfs.AssetFS
}

// Append add dashboard routes on a router.
func (g DashboardHandler) Append(router *mux.Router) {
	if g.Assets == nil {
		log.WithoutContext().Error("No assets for dashboard")
		return
	}

	// Expose dashboard
	router.Methods(http.MethodGet).
		Path("/").
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
 
 import (
 	"net/http"
+	"net/url"
 
 	"github.com/containous/traefik/v2/pkg/log"
 	assetfs "github.com/elazarl/go-bindata-assetfs"
@@ -23,11 +24,29 @@
 	// Expose dashboard
 	router.Methods(http.MethodGet).
 		Path("/").
-		HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
-			http.Redirect(response, request, request.Header.Get("X-Forwarded-Prefix")+"/dashboard/", http.StatusFound)
+		HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
+			http.Redirect(resp, req, safePrefix(req)+"/dashboard/", http.StatusFound)
 		})
 
 	router.Methods(http.MethodGet).
 		PathPrefix("/dashboard/").
 		Handler(http.StripPrefix("/dashboard/", http.FileServer(g.Assets)))
 }
+
+func safePrefix(req *http.Request) string {
+	prefix := req.Header.Get("X-Forwarded-Prefix")
+	if prefix == "" {
+		return ""
+	}
+
+	parse, err := url.Parse(prefix)
+	if err != nil {
+		return ""
+	}
+
+	if parse.Host != "" {
+		return ""
+	}
+
+	return parse.Path
+}
```
