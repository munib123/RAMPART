# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4439_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4439_6`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-6 of the vulnerable file.

require('./1-normal');
require('./2-with-init');
require('./3-symbol-property');
require('./4-array-params');
require('./5-array-value');
require('./6-option-params');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,3 +4,4 @@
 require('./4-array-params');
 require('./5-array-value');
 require('./6-option-params');
+require('./7-no-proto-polution');
```
