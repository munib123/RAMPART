# CrossVul Fix Pair: Improper Restriction of Rendered UI Layers or Frames in go
**Pair ID:** 4282_0
**Vulnerability Class:** UI Redressing (Clickjacking)
**CWE:** CWE-1021
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4282_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Rendered UI Layers or Frames - A web application is expected to place restrictions on whether it is allowed to be rendered within frames, iframes, objects, embed or applet elements.

## Vulnerable Code
```go
Lines 138-178 of the vulnerable file.

	router.HandleFunc("/impersonate", mid.Use(as.Impersonate, mid.RequirePermission(models.PermissionModifySystem), mid.RequireLogin))
	// Create the API routes
	api := api.NewServer(
		api.WithWorker(as.worker),
		api.WithLimiter(as.limiter),
	)
	router.PathPrefix("/api/").Handler(api)

	// Setup static file serving
	router.PathPrefix("/").Handler(http.FileServer(unindexed.Dir("./static/")))

	// Setup CSRF Protection
	csrfKey := []byte(as.config.CSRFKey)
	if len(csrfKey) == 0 {
		csrfKey = []byte(auth.GenerateSecureKey(auth.APIKeyLength))
	}
	csrfHandler := csrf.Protect(csrfKey,
		csrf.FieldName("csrf_token"),
		csrf.Secure(as.config.UseTLS))
	adminHandler := csrfHandler(router)
	adminHandler = mid.Use(adminHandler.ServeHTTP, mid.CSRFExceptions, mid.GetContext)

	// Setup GZIP compression
	gzipWrapper, _ := gziphandler.NewGzipLevelHandler(gzip.BestCompression)
	adminHandler = gzipWrapper(adminHandler)

	// Setup logging
	adminHandler = handlers.CombinedLoggingHandler(log.Writer(), adminHandler)
	as.server.Handler = adminHandler
}

type templateParams struct {
	Title        string
	Flashes      []interface{}
	User         models.User
	Token        string
	Version      string
	ModifySystem bool
}

// newTemplateParams returns the default template parameters for a user and
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,7 +155,7 @@
 		csrf.FieldName("csrf_token"),
 		csrf.Secure(as.config.UseTLS))
 	adminHandler := csrfHandler(router)
-	adminHandler = mid.Use(adminHandler.ServeHTTP, mid.CSRFExceptions, mid.GetContext)
+	adminHandler = mid.Use(adminHandler.ServeHTTP, mid.CSRFExceptions, mid.GetContext, mid.ApplySecurityHeaders)
 
 	// Setup GZIP compression
 	gzipWrapper, _ := gziphandler.NewGzipLevelHandler(gzip.BestCompression)
```
