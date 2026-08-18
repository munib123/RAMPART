# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 1105_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1105_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 1-11 of the vulnerable file.

import * as crypto from 'crypto';

export class Crypto {
    static hash256(message: Buffer): Buffer { 
        let hash1 = crypto.createHash('sha256');
        let hash2 = crypto.createHash('sha256');
        hash1.update(message);
        hash2.update(hash1.digest());
        return Buffer.from(hash2.digest().toJSON().data.reverse());
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,9 +1,9 @@
-import * as crypto from 'crypto';
+import * as crypto from "crypto";
 
 export class Crypto {
-    static hash256(message: Buffer): Buffer { 
-        let hash1 = crypto.createHash('sha256');
-        let hash2 = crypto.createHash('sha256');
+    public static hash256(message: Buffer): Buffer {
+        const hash1 = crypto.createHash("sha256");
+        const hash2 = crypto.createHash("sha256");
         hash1.update(message);
         hash2.update(hash1.digest());
         return Buffer.from(hash2.digest().toJSON().data.reverse());
```
