# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 2477_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2477_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-22 of the vulnerable file.

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const confinit = require("../index");
const path = require("path");
class Section1Config {
    constructor() {
        this.url = "";
    }
    validate() {
        if (!this.url) {
            throw new Error("Section 1 url not set.");
        }
    }
}
exports.Section1Config = Section1Config;
class WebServerConfig {
    constructor() {
        this.port = 3000;
        const envPort = process.env.PORT;
        if (envPort) {
            this.port = parseInt(envPort, 10);
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 "use strict";
+// See README.md for details
 Object.defineProperty(exports, "__esModule", { value: true });
 const confinit = require("../index");
 const path = require("path");
@@ -36,11 +37,14 @@
         if (!env) {
             env = process.env;
         }
+        // Enable config file
         if (env.config) {
             const configFile = path.resolve(process.cwd(), env.config);
             confinit.applyConfigFile(this, configFile);
         }
+        // Enable environment variables
         confinit.applyEnvVariables(this, process.env, "cfg_");
+        // Enable command arguments
         confinit.applyCommandArgs(this, process.argv);
         confinit.validate(this);
     }
```
