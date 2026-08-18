# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in json
**Pair ID:** 2007_4
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2007_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "async-git",
  "version": "1.13.0",
  "description": "👾 Retrieve data from current git repository",
  "keywords": [
    "git",
    "github",
    "bitbucket",
    "gitlab",
    "info",
    "async",
    "promise",
    "commit",
    "branch",
    "author",
    "git log",
    "source control"
  ],
  "author": "omrilotan",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/omrilotan/async-git.git"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "async-git",
-  "version": "1.13.0",
+  "version": "1.13.1",
   "description": "👾 Retrieve data from current git repository",
   "keywords": [
     "git",
```
