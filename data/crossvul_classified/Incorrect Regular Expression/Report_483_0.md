# CrossVul Fix Pair: Incorrect Regular Expression in json
**Pair ID:** 483_0
**Vulnerability Class:** Incorrect Regular Expression
**CWE:** CWE-185
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `483_0`)

## Vulnerability Information & PoC

## Description
Incorrect Regular Expression - When the regular expression is used in protection mechanisms such as filtering or validation, this may allow an attacker to bypass the intended restrictions on the incoming data.

## Vulnerable Code
```json
Lines 1-24 of the vulnerable file.

{
  "name": "uap-core",
  "description": "The regex file necessary to build language ports of Browserscope's user agent parser.",
  "version": "0.5.0",
  "maintainers": [
    {
      "name": "Tobie Langel",
      "email": "tobie.langel@gmail.com",
      "web": "http://tobielangel.com"
    },
    {
      "name": "Lindsey Simon",
      "email": "lsimon@commoner.com",
      "web": "http://www.idreamofuni.com"
    }
  ],
  "repository": {
    "type": "git",
    "url": "http://github.com/ua-parser/uap-core.git"
  },
  "licenses": [
    {
      "type": "Apache-2.0",
      "url": "https://raw.github.com/ua-parser/uap-core/master/LICENSE"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 {
   "name": "uap-core",
   "description": "The regex file necessary to build language ports of Browserscope's user agent parser.",
-  "version": "0.5.0",
+  "version": "0.6.0",
   "maintainers": [
     {
       "name": "Tobie Langel",
```
