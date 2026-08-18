# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 5027_6
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5027_6`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 31-71 of the vulnerable file.

      email: 'e',
      auth: 'dTpw',
      alwaysAuth: false
    })
    t.equal(registry, 'https://registry.npmjs.org/')
  })

  npm.config.set('scope', 'test')
  npm.config.set('@test:registry', 'http://reg.npm/design/-/rewrite/')
  npm.config.set('//reg.npm/design/-/rewrite/:_authToken', 'a-token')
  mapRegistry('simple', npm.config, function (er, uri, auth, registry) {
    t.ifError(er, 'mapRegistryToURI worked')
    t.equal(uri, 'http://reg.npm/design/-/rewrite/simple')
    t.deepEqual(auth, {
      scope: '//reg.npm/design/-/rewrite/',
      token: 'a-token',
      username: undefined,
      password: undefined,
      email: undefined,
      auth: undefined,
      alwaysAuth: undefined
    })
    t.equal(registry, 'http://reg.npm/design/-/rewrite/')
  })

  npm.config.set('scope', '')
  npm.config.set('@test2:registry', 'http://reg.npm/-/rewrite/')
  npm.config.set('//reg.npm/-/rewrite/:_authToken', 'b-token')
  mapRegistry('@test2/easy', npm.config, function (er, uri, auth, registry) {
    t.ifError(er, 'mapRegistryToURI worked')
    t.equal(uri, 'http://reg.npm/-/rewrite/@test2%2feasy')
    t.deepEqual(auth, {
      scope: '//reg.npm/-/rewrite/',
      token: 'b-token',
      username: undefined,
      password: undefined,
      email: undefined,
      auth: undefined,
      alwaysAuth: undefined
    })
    t.equal(registry, 'http://reg.npm/-/rewrite/')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,7 +48,7 @@
       password: undefined,
       email: undefined,
       auth: undefined,
-      alwaysAuth: undefined
+      alwaysAuth: false
     })
     t.equal(registry, 'http://reg.npm/design/-/rewrite/')
   })
@@ -66,7 +66,7 @@
       password: undefined,
       email: undefined,
       auth: undefined,
-      alwaysAuth: undefined
+      alwaysAuth: false
     })
     t.equal(registry, 'http://reg.npm/-/rewrite/')
   })
@@ -84,8 +84,83 @@
       password: undefined,
       email: undefined,
       auth: undefined,
-      alwaysAuth: undefined
+      alwaysAuth: false
     })
     t.equal(registry, 'http://reg.npm/design/-/rewrite/relative/')
   })
 })
+
+test('mapToRegistry token scoping', function (t) {
+  npm.config.set('scope', '')
+  npm.config.set('registry', 'https://reg.npm/')
+  npm.config.set('//reg.npm/:_authToken', 'r-token')
+
+  t.test('pass token to registry host', function (t) {
+    mapRegistry(
+      'https://reg.npm/packages/e/easy-1.0.0.tgz',
+      npm.config,
+      function (er, uri, auth, registry) {
+        t.ifError(er, 'mapRegistryToURI worked')
+        t.equal(uri, 'https://reg.npm/packages/e/easy-1.0.0.tgz')
+        t.deepEqual(auth, {
+          scope: '//reg.npm/',
+          token: 'r-token',
+          username: undefined,
+          password: undefined,
+          email: undefined,
+          auth: undefined,
+          alwaysAuth: false
+        })
+        t.equal(registry, 'https://reg.npm/')
+      }
+    )
+    t.end()
+  })
+
+  t.test("don't pass token to non-registry host", function (t) {
+    mapRegistry(
+      'https://butts.lol/packages/e/easy-1.0.0.tgz',
+      npm.config,
+      function (er, uri, auth, registry) {
+        t.ifError(er, 'mapRegistryToURI worked')
+        t.equal(uri, 'https://butts.lol/packages/e/easy-1.0.0.tgz')
+        t.deepEqual(auth, {
+          scope: '//reg.npm/',
+          token: undefined,
+          username: undefined,
+          password: undefined,
+          email: undefined,
+          auth: undefined,
+          alwaysAuth: false
+        })
+        t.equal(registry, 'https://reg.npm/')
+      }
+    )
+    t.end()
+  })
+
+  t.test('pass token to non-registry host with always-auth', function (t) {
+    npm.config.set('always-auth', true)
+    mapRegistry(
+      'https://butts.lol/packages/e/easy-1.0.0.tgz',
+      npm.config,
+      function (er, uri, auth, registry) {
+        t.ifError(er, 'mapRegistryToURI worked')
+        t.equal(uri, 'https://butts.lol/packages/e/easy-1.0.0.tgz')
+        t.deepEqual(auth, {
+          scope: '//reg.npm/',
+          token: 'r-token',
+          username: undefined,
+          password: undefined,
+          email: undefined,
+          auth: undefined,
+          alwaysAuth: true
+        })
+        t.equal(registry, 'https://reg.npm/')
+      }
+    )
+    t.end()
+  })
+
+  t.end()
+})
```
