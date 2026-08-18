# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4687_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4687_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 28-49 of the vulnerable file.

# endif
}

int pure_memcmp(const void * const b1_, const void * const b2_, size_t len)
{
    const unsigned char *b1 = (const unsigned char *) b1_;
    const unsigned char *b2 = (const unsigned char *) b2_;
    size_t               i;
    unsigned char        d = (unsigned char) 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (int) ((1 & ((d - 1) >> 8)) - 1);
}

#endif

int pure_strcmp(const char * const s1, const char * const s2)
{
    return pure_memcmp(s1, s2, strlen(s1) + 1U);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,5 +45,9 @@
 
 int pure_strcmp(const char * const s1, const char * const s2)
 {
-    return pure_memcmp(s1, s2, strlen(s1) + 1U);
+    const size_t s1_len = strlen(s1);
+    const size_t s2_len = strlen(s2);
+    const size_t len = (s1_len < s2_len) ? s1_len : s2_len;
+
+    return pure_memcmp(s1, s2, len + 1);
 }
```
