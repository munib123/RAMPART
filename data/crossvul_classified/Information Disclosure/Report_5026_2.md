# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 5026_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5026_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 1-41 of the vulnerable file.

var assert = require('assert')

var toNerfDart = require('./nerf-dart.js')

module.exports = getCredentialsByURI

function getCredentialsByURI (uri) {
  assert(uri && typeof uri === 'string', 'registry URL is required')
  var nerfed = toNerfDart(uri)
  var defnerf = toNerfDart(this.get('registry'))

  // hidden class micro-optimization
  var c = {
    scope: nerfed,
    token: undefined,
    password: undefined,
    username: undefined,
    email: undefined,
    auth: undefined,
    alwaysAuth: undefined
  }

  if (this.get(nerfed + ':_authToken')) {
    c.token = this.get(nerfed + ':_authToken')
    // the bearer token is enough, don't confuse things
    return c
  }

  // Handle the old-style _auth=<base64> style for the default
  // registry, if set.
  //
  // XXX(isaacs): Remove when npm 1.4 is no longer relevant
  var authDef = this.get('_auth')
  var userDef = this.get('username')
  var passDef = this.get('_password')
  if (authDef && !(userDef && passDef)) {
    authDef = new Buffer(authDef, 'base64').toString()
    authDef = authDef.split(':')
    userDef = authDef.shift()
    passDef = authDef.join(':')
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,14 @@
     email: undefined,
     auth: undefined,
     alwaysAuth: undefined
+  }
+
+  // used to override scope matching for tokens as well as legacy auth
+  if (this.get(nerfed + ':always-auth') !== undefined) {
+    var val = this.get(nerfed + ':always-auth')
+    c.alwaysAuth = val === 'false' ? false : !!val
+  } else if (this.get('always-auth') !== undefined) {
+    c.alwaysAuth = this.get('always-auth')
   }
 
   if (this.get(nerfed + ':_authToken')) {
@@ -58,13 +66,6 @@
     c.email = this.get('email')
   }
 
-  if (this.get(nerfed + ':always-auth') !== undefined) {
-    var val = this.get(nerfed + ':always-auth')
-    c.alwaysAuth = val === 'false' ? false : !!val
-  } else if (this.get('always-auth') !== undefined) {
-    c.alwaysAuth = this.get('always-auth')
-  }
-
   if (c.username && c.password) {
     c.auth = new Buffer(c.username + ':' + c.password).toString('base64')
   }
```
