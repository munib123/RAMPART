# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1281_7
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1281_7`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 71-90 of the vulnerable file.

#define atom_expr 324
#define atom 325
#define testlist_comp 326
#define trailer 327
#define subscriptlist 328
#define subscript 329
#define sliceop 330
#define exprlist 331
#define testlist 332
#define dictorsetmaker 333
#define classdef 334
#define arglist 335
#define argument 336
#define comp_iter 337
#define sync_comp_for 338
#define comp_for 339
#define comp_if 340
#define encoding_decl 341
#define yield_expr 342
#define yield_arg 343
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,3 +88,7 @@
 #define encoding_decl 341
 #define yield_expr 342
 #define yield_arg 343
+#define func_body_suite 344
+#define func_type_input 345
+#define func_type 346
+#define typelist 347
```
