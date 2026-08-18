# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in json
**Pair ID:** 226_5
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `226_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "macaddress",
  "version": "0.2.9",
  "description": "Get the MAC addresses (hardware addresses) of the hosts network interfaces.",
  "main": "index.js",
  "scripts": {
    "test": "node test.js"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/scravy/node-macaddress.git"
  },
  "keywords": [
    "mac",
    "mac-address",
    "hardware-address",
    "network",
    "system"
  ],
  "author": "Julian Fleischer",
  "license": "MIT",
  "bugs": {
    "url": "https://github.com/scravy/node-macaddress/issues"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "macaddress",
-  "version": "0.2.9",
+  "version": "0.2.10",
   "description": "Get the MAC addresses (hardware addresses) of the hosts network interfaces.",
   "main": "index.js",
   "scripts": {
```
