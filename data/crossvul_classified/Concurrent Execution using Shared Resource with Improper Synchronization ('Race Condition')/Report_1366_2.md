# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in rust
**Pair ID:** 1366_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1366_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```rust
Lines 1-22 of the vulnerable file.

use core::ops::{Add, AddAssign, Mul, MulAssign};

const SECP256K1_N_0: u32 = 0xD0364141;
const SECP256K1_N_1: u32 = 0xBFD25E8C;
const SECP256K1_N_2: u32 = 0xAF48A03B;
const SECP256K1_N_3: u32 = 0xBAAEDCE6;
const SECP256K1_N_4: u32 = 0xFFFFFFFE;
const SECP256K1_N_5: u32 = 0xFFFFFFFF;
const SECP256K1_N_6: u32 = 0xFFFFFFFF;
const SECP256K1_N_7: u32 = 0xFFFFFFFF;

const SECP256K1_N_C_0: u32 = !SECP256K1_N_0 + 1;
const SECP256K1_N_C_1: u32 = !SECP256K1_N_1;
const SECP256K1_N_C_2: u32 = !SECP256K1_N_2;
const SECP256K1_N_C_3: u32 = !SECP256K1_N_3;
const SECP256K1_N_C_4: u32 = 1;

const SECP256K1_N_H_0: u32 = 0x681B20A0;
const SECP256K1_N_H_1: u32 = 0xDFE92F46;
const SECP256K1_N_H_2: u32 = 0x57A4501D;
const SECP256K1_N_H_3: u32 = 0x5D576E73;
const SECP256K1_N_H_4: u32 = 0xFFFFFFFF;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 use core::ops::{Add, AddAssign, Mul, MulAssign};
+use subtle::Choice;
 
 const SECP256K1_N_0: u32 = 0xD0364141;
 const SECP256K1_N_1: u32 = 0xBFD25E8C;
@@ -69,21 +70,21 @@
 
     #[must_use]
     fn check_overflow(&self) -> bool {
-        let mut yes: bool = false;
-        let mut no: bool = false;
-        no = no || (self.0[7] < SECP256K1_N_7); /* No need for a > check. */
-        no = no || (self.0[6] < SECP256K1_N_6); /* No need for a > check. */
-        no = no || (self.0[5] < SECP256K1_N_5); /* No need for a > check. */
-        no = no || (self.0[4] < SECP256K1_N_4);
-        yes = yes || ((self.0[4] > SECP256K1_N_4) && !no);
-        no = no || ((self.0[3] < SECP256K1_N_3) && !yes);
-        yes = yes || ((self.0[3] > SECP256K1_N_3) && !no);
-        no = no || ((self.0[2] < SECP256K1_N_2) && !yes);
-        yes = yes || ((self.0[2] > SECP256K1_N_2) && !no);
-        no = no || ((self.0[1] < SECP256K1_N_1) && !yes);
-        yes = yes || ((self.0[1] > SECP256K1_N_1) && !no);
-        yes = yes || ((self.0[0] >= SECP256K1_N_0) && !no);
-        return yes;
+        let mut yes: Choice = 0.into();
+        let mut no: Choice = 0.into();
+        no |= Choice::from((self.0[7] < SECP256K1_N_7) as u8); /* No need for a > check. */
+        no |= Choice::from((self.0[6] < SECP256K1_N_6) as u8); /* No need for a > check. */
+        no |= Choice::from((self.0[5] < SECP256K1_N_5) as u8); /* No need for a > check. */
+        no |= Choice::from((self.0[4] < SECP256K1_N_4) as u8);
+        yes |= Choice::from((self.0[4] > SECP256K1_N_4) as u8) & !no;
+        no |= Choice::from((self.0[3] < SECP256K1_N_3) as u8) & !yes;
+        yes |= Choice::from((self.0[3] > SECP256K1_N_3) as u8) & !no;
+        no |= Choice::from((self.0[2] < SECP256K1_N_2) as u8) & !yes;
+        yes |= Choice::from((self.0[2] > SECP256K1_N_2) as u8) & !no;
+        no |= Choice::from((self.0[1] < SECP256K1_N_1) as u8) & !yes;
+        yes |= Choice::from((self.0[1] > SECP256K1_N_1) as u8) & !no;
+        yes |= Choice::from((self.0[0] >= SECP256K1_N_0) as u8) & !no;
+        return yes.into();
     }
 
     #[must_use]
```
