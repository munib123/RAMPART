# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 618_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `618_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 26-60 of the vulnerable file.

                      "uglify-js"               : "2.6.2",
                      "formidable"              : "1.0.17",
                      "log4js"                  : "0.6.35",
                      "cheerio"                 : "0.20.0",
                      "async-stacktrace"        : "0.0.2",
                      "npm"                     : "4.0.2",
                      "ejs"                     : "2.5.7",
                      "graceful-fs"             : "4.1.3",
                      "slide"                   : "1.1.6",
                      "semver"                  : "5.1.0",
                      "security"                : "1.0.0",
                      "tinycon"                 : "0.0.1",
                      "underscore"              : "1.8.3",
                      "unorm"                   : "1.4.1",
                      "languages4translatewiki" : "0.1.3",
                      "swagger-node-express"    : "2.1.3",
                      "channels"                : "0.0.4",
                      "jsonminify"              : "0.4.1",
                      "measured"                : "1.1.0",
                      "mocha"                   : "2.4.5",
                      "supertest"               : "1.2.0"
                     },
  "bin":             { "etherpad-lite": "./node/server.js" },
  "devDependencies": {
                      "wd"      : "0.3.11"
                     },
  "engines"        : { "node" : ">=0.10.0",
                       "npm"  : ">=1.0"
                     },
  "repository"     : { "type" : "git",
                       "url" : "http://github.com/ether/etherpad-lite.git"
                     },
  "version"        : "1.6.2",
  "license"        : "Apache-2.0"
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,8 @@
                       "jsonminify"              : "0.4.1",
                       "measured"                : "1.1.0",
                       "mocha"                   : "2.4.5",
-                      "supertest"               : "1.2.0"
+                      "supertest"               : "1.2.0",
+                      "is-var-name"             : "1.0.0"
                      },
   "bin":             { "etherpad-lite": "./node/server.js" },
   "devDependencies": {
```
