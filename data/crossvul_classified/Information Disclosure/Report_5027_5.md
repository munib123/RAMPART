# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 5027_5
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5027_5`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 56-102 of the vulnerable file.

  npmconf.load(common.builtin, function (er, conf) {
    t.ifError(er, "configuration loaded")

    t.throws(function () {
      conf.setCredentialsByURI(URI, {})
    }, "enforced missing credentials")

    t.end()
  })
})

test("set with token", function (t) {
  npmconf.load(common.builtin, function (er, conf) {
    t.ifError(er, "configuration loaded")

    t.doesNotThrow(function () {
      conf.setCredentialsByURI(URI, {token : "simple-token"})
    }, "needs only token")

    var expected = {
      scope      : "//registry.lvh.me:8661/",
      token      : "simple-token",
      username   : undefined,
      password   : undefined,
      email      : undefined,
      auth       : undefined,
      alwaysAuth : undefined
    }

    t.same(conf.getCredentialsByURI(URI), expected, "got bearer token and scope")

    t.end()
  })
})

test("clear with token", function (t) {
  npmconf.load(common.builtin, function (er, conf) {
    t.ifError(er, "configuration loaded")

    t.doesNotThrow(function () {
      conf.setCredentialsByURI(URI, {token : "simple-token"})
    }, "needs only token")

    t.doesNotThrow(function () {
      conf.clearCredentialsByURI(URI)
    }, "needs only URI")

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,13 +73,13 @@
     }, "needs only token")
 
     var expected = {
-      scope      : "//registry.lvh.me:8661/",
-      token      : "simple-token",
-      username   : undefined,
-      password   : undefined,
-      email      : undefined,
-      auth       : undefined,
-      alwaysAuth : undefined
+      scope: '//registry.lvh.me:8661/',
+      token: 'simple-token',
+      username: undefined,
+      password: undefined,
+      email: undefined,
+      auth: undefined,
+      alwaysAuth: false
     }
 
     t.same(conf.getCredentialsByURI(URI), expected, "got bearer token and scope")
```
