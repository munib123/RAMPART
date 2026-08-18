# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 1105_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1105_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 1-11 of the vulnerable file.

export class Script {
    static opcodes = {
        OP_0: 0,
        OP_16: 96,
        OP_PUSHDATA1: 76,
        OP_PUSHDATA2: 77,
        OP_PUSHDATA4: 78,
        OP_1NEGATE : 79,
        OP_RETURN: 106,
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,7 @@
         OP_PUSHDATA1: 76,
         OP_PUSHDATA2: 77,
         OP_PUSHDATA4: 78,
-        OP_1NEGATE : 79,
+        OP_1NEGATE: 79,
         OP_RETURN: 106,
     }
 }
```
