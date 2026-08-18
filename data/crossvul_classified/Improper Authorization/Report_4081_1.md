# CrossVul Fix Pair: Improper Authorization in json
**Pair ID:** 4081_1
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4081_1`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```json
Lines 22-47 of the vulnerable file.

    "url": "http://github.com/auth0/express-jwt/issues"
  },
  "author": {
    "name": "Matias Woloski",
    "email": "matias@auth0.com",
    "url": "https://www.auth0.com/"
  },
  "license": "MIT",
  "main": "./lib",
  "dependencies": {
    "async": "^1.5.0",
    "express-unless": "^0.3.0",
    "jsonwebtoken": "^8.1.0",
    "lodash.set": "^4.0.0"
  },
  "devDependencies": {
    "conventional-changelog": "~1.1.0",
    "mocha": "^7.1.1"
  },
  "engines": {
    "node": ">= 0.4.0"
  },
  "scripts": {
    "test": "node_modules/.bin/mocha --reporter spec"
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
     "mocha": "^7.1.1"
   },
   "engines": {
-    "node": ">= 0.4.0"
+    "node": ">= 8.0.0"
   },
   "scripts": {
     "test": "node_modules/.bin/mocha --reporter spec"
```
