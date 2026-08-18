# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in json
**Pair ID:** 713_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `713_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```json
Lines 1-6 of the vulnerable file.

{
  "spec_dir": "tests",
  "spec_files": [],
  "stopSpecOnExpectationFailure": false,
  "random": false
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,8 @@
 {
   "spec_dir": "tests",
-  "spec_files": [],
+  "spec_files": [
+    "UtilsTests.js"
+  ],
   "stopSpecOnExpectationFailure": false,
   "random": false
 }
```
