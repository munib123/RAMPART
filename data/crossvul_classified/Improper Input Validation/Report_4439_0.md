# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4439_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4439_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-23 of the vulnerable file.

import { normalizeDescriptor } from './utility/setup';
import { getNonEmptyPropName } from './utility/common';
function generate(target, hierarchies, forceOverride) {
    let current = target;
    hierarchies.forEach(info => {
        const descriptor = normalizeDescriptor(info);
        const { value, type, create, override, created, skipped, got } = descriptor;
        const name = getNonEmptyPropName(current, descriptor);
        if (forceOverride || override || !current[name] || typeof current[name] !== 'object') {
            const obj = value ? value :
                type ? new type() :
                    create ? create.call(current, current, name) :
                        {};
            current[name] = obj;
            if (created) {
                created.call(current, current, name, obj);
            }
        }
        else {
            if (skipped) {
                skipped.call(current, current, name, current[name]);
            }
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,12 +1,17 @@
 import { normalizeDescriptor } from './utility/setup';
 import { getNonEmptyPropName } from './utility/common';
+const propProto = '__proto__';
 function generate(target, hierarchies, forceOverride) {
     let current = target;
     hierarchies.forEach(info => {
         const descriptor = normalizeDescriptor(info);
         const { value, type, create, override, created, skipped, got } = descriptor;
         const name = getNonEmptyPropName(current, descriptor);
-        if (forceOverride || override || !current[name] || typeof current[name] !== 'object') {
+        if (forceOverride ||
+            override ||
+            !current[name] ||
+            typeof current[name] !== 'object' ||
+            (name === propProto && current[name] === Object.prototype)) {
             const obj = value ? value :
                 type ? new type() :
                     create ? create.call(current, current, name) :
```
