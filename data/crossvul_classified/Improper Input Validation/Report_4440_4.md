# CrossVul Fix Pair: Improper Input Validation in shell
**Pair ID:** 4440_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4440_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```bash
Lines 1-5 of the vulnerable file.

#!/bin/bash
node tests/testHas.js
node tests/testGet.js
node tests/testExports.js
node tests/testSet.js
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,3 +3,4 @@
 node tests/testGet.js
 node tests/testExports.js
 node tests/testSet.js
+node tests/testVulnerability.js
```
