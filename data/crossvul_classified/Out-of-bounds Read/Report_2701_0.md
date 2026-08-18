# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2701_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2701_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 264-283 of the vulnerable file.

#define ND_TTEST_16BITS(p) ND_TTEST2(*(p), 2)
#define ND_TCHECK_16BITS(p) ND_TCHECK2(*(p), 2)

#define ND_TTEST_24BITS(p) ND_TTEST2(*(p), 3)
#define ND_TCHECK_24BITS(p) ND_TCHECK2(*(p), 3)

#define ND_TTEST_32BITS(p) ND_TTEST2(*(p), 4)
#define ND_TCHECK_32BITS(p) ND_TCHECK2(*(p), 4)

#define ND_TTEST_40BITS(p) ND_TTEST2(*(p), 5)
#define ND_TCHECK_40BITS(p) ND_TCHECK2(*(p), 5)

#define ND_TTEST_48BITS(p) ND_TTEST2(*(p), 6)
#define ND_TCHECK_48BITS(p) ND_TCHECK2(*(p), 6)

#define ND_TTEST_56BITS(p) ND_TTEST2(*(p), 7)
#define ND_TCHECK_56BITS(p) ND_TCHECK2(*(p), 7)

#define ND_TTEST_64BITS(p) ND_TTEST2(*(p), 8)
#define ND_TCHECK_64BITS(p) ND_TCHECK2(*(p), 8)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -281,3 +281,6 @@
 
 #define ND_TTEST_64BITS(p) ND_TTEST2(*(p), 8)
 #define ND_TCHECK_64BITS(p) ND_TCHECK2(*(p), 8)
+
+#define ND_TTEST_128BITS(p) ND_TTEST2(*(p), 16)
+#define ND_TCHECK_128BITS(p) ND_TCHECK2(*(p), 16)
```
