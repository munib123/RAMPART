# CrossVul Fix Pair: Out-of-bounds Read in javascript
**Pair ID:** 4256_5
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4256_5`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```javascript
Lines 57-97 of the vulnerable file.

// CHECK-NEXT:     JmpTrue           L5, r9
// CHECK-NEXT: L2:
// CHECK-NEXT:     CompleteGenerator
// CHECK-NEXT:     Ret               r5
// CHECK-NEXT: L4:
// CHECK-NEXT:     CompleteGenerator
// CHECK-NEXT:     Ret               r7
// CHECK-NEXT: L1:
// CHECK-NEXT:     CompleteGenerator
// CHECK-NEXT:     Ret               r8

function *args() {
  yield arguments[0];
}

// CHECK-LABEL: NCFunction<args>(1 params, 3 registers, 0 symbols):
// CHECK-NEXT:     CreateEnvironment r0
// CHECK-NEXT:     CreateGenerator   r1, r0, 4
// CHECK-NEXT:     Ret               r1

// CHECK-LABEL: Function<?anon_1_args>(1 params, 7 registers, 0 symbols):
// CHECK-NEXT: Offset in debug table: source 0x{{.*}}, lexical 0x0000
// CHECK-NEXT:     StartGenerator
// CHECK-NEXT:     CreateEnvironment r0
// CHECK-NEXT:     LoadConstUndefined r0
// CHECK-NEXT:     LoadConstZero     r1
// CHECK-NEXT:     ResumeGenerator   r3, r2
// CHECK-NEXT:     Mov               r4, r2
// CHECK-NEXT:     JmpTrue           L1, r4
// CHECK-NEXT:     Mov               r2, r0
// CHECK-NEXT:     GetArgumentsPropByVal r4, r1, r2
// CHECK-NEXT:     SaveGenerator     L2
// CHECK-NEXT:     Ret               r4
// CHECK-NEXT: L2:
// CHECK-NEXT:     ResumeGenerator   r2, r5
// CHECK-NEXT:     Mov               r4, r5
// CHECK-NEXT:     JmpTrue           L3, r4
// CHECK-NEXT:     CompleteGenerator
// CHECK-NEXT:     Ret               r0
// CHECK-NEXT: L3:
// CHECK-NEXT:     CompleteGenerator
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,7 +74,7 @@
 // CHECK-NEXT:     CreateGenerator   r1, r0, 4
 // CHECK-NEXT:     Ret               r1
 
-// CHECK-LABEL: Function<?anon_1_args>(1 params, 7 registers, 0 symbols):
+// CHECK-LABEL: Function<?anon_0_args>(1 params, 7 registers, 0 symbols):
 // CHECK-NEXT: Offset in debug table: source 0x{{.*}}, lexical 0x0000
 // CHECK-NEXT:     StartGenerator
 // CHECK-NEXT:     CreateEnvironment r0
```
