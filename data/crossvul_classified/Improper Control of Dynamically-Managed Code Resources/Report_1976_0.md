# CrossVul Fix Pair: Improper Control of Dynamically-Managed Code Resources in json
**Pair ID:** 1976_0
**Vulnerability Class:** Improper Control of Dynamically-Managed Code Resources
**CWE:** CWE-913
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1976_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Dynamically-Managed Code Resources - Many languages offer powerful features that allow the programmer to dynamically create or modify existing code, or resources used by code such as variables and objects.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "config-shield",
  "version": "0.2.1",
  "description": "Store and retrieve data sensative in nature",
  "main": "./lib/index.js",
  "scripts": {
    "test": "mocha",
    "start": "npm run cli",
    "cli": "node ./scripts/cli.js"
  },
  "bin": {
    "config-shield": "./bin/config-shield",
    "cshield": "./bin/config-shield"
  },
  "repository": {
    "type": "git",
    "url": "git@github.com:godaddy/node-config-shield.git"
  },
  "author": {
    "name": "Aaron Silvas"
  },
  "devDependencies": {
    "mocha": "^7.2.0"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "config-shield",
-  "version": "0.2.1",
+  "version": "0.2.2",
   "description": "Store and retrieve data sensative in nature",
   "main": "./lib/index.js",
   "scripts": {
@@ -29,5 +29,8 @@
       "name": "asilvas",
       "email": "asilvas@godaddy.com"
     }
-  ]
+  ],
+  "dependencies": {
+    "json5": "^2.1.3"
+  }
 }
```
