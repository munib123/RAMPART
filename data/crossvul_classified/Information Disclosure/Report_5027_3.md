# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 5027_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5027_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 31-56 of the vulnerable file.


    log.silly("mapToRegistry", "scope (from config)", scope)

    registry = config.get(scope + ":registry")
    if (!registry) {
      log.verbose("mapToRegistry", "no registry URL found in config for scope", scope)
    }
  }

  // ...and finally use the default registry
  if (!registry) {
    log.silly("mapToRegistry", "using default registry")
    registry = config.get("registry")
  }

  log.silly("mapToRegistry", "registry", registry)

  var auth = config.getCredentialsByURI(registry)

  // normalize registry URL so resolution doesn't drop a piece of registry URL
  var normalized = registry.slice(-1) !== "/" ? registry+"/" : registry
  var uri = url.resolve(normalized, name)
  log.silly("mapToRegistry", "uri", uri)

  cb(null, uri, auth, normalized)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,9 +48,53 @@
   var auth = config.getCredentialsByURI(registry)
 
   // normalize registry URL so resolution doesn't drop a piece of registry URL
-  var normalized = registry.slice(-1) !== "/" ? registry+"/" : registry
-  var uri = url.resolve(normalized, name)
-  log.silly("mapToRegistry", "uri", uri)
+  var normalized = registry.slice(-1) !== '/' ? registry + '/' : registry
+  var uri
+  log.silly('mapToRegistry', 'data', data)
+  if (data.type === 'remote') {
+    uri = data.spec
+  } else {
+    uri = url.resolve(normalized, name)
+  }
 
-  cb(null, uri, auth, normalized)
+  log.silly('mapToRegistry', 'uri', uri)
+
+  cb(null, uri, scopeAuth(uri, registry, auth), normalized)
 }
+
+function scopeAuth (uri, registry, auth) {
+  var cleaned = {
+    scope: auth.scope,
+    email: auth.email,
+    alwaysAuth: auth.alwaysAuth,
+    token: undefined,
+    username: undefined,
+    password: undefined,
+    auth: undefined
+  }
+
+  var requestHost
+  var registryHost
+
+  if (auth.token || auth.auth || (auth.username && auth.password)) {
+    requestHost = url.parse(uri).hostname
+    registryHost = url.parse(registry).hostname
+
+    if (requestHost === registryHost) {
+      cleaned.token = auth.token
+      cleaned.auth = auth.auth
+      cleaned.username = auth.username
+      cleaned.password = auth.password
+    } else if (auth.alwaysAuth) {
+      log.verbose('scopeAuth', 'alwaysAuth set for', registry)
+      cleaned.token = auth.token
+      cleaned.auth = auth.auth
+      cleaned.username = auth.username
+      cleaned.password = auth.password
+    } else {
+      log.silly('scopeAuth', uri, "doesn't share host with registry", registry)
+    }
+  }
+
+  return cleaned
+}
```
