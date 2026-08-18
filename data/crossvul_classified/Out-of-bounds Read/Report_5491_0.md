# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5491_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5491_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 99-127 of the vulnerable file.

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#if defined(JAS_HAVE_SYS_TYPES_H)
#include <sys/types.h>
#endif

#define jas_uchar unsigned char
#define jas_uint unsigned int
#define jas_ulong unsigned long
#define jas_longlong long long
#define jas_ulonglong unsigned long long

/* The below macro is intended to be used for type casts.  By using this
  macro, type casts can be easily located in the source code with
  tools like "grep". */
#define	JAS_CAST(t, e) \
	((t) (e))

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,6 +116,10 @@
 #define	JAS_CAST(t, e) \
 	((t) (e))
 
+/* The number of bits in the integeral type uint_fast32_t. */
+/* NOTE: This could underestimate the size on some exotic architectures. */
+#define JAS_UINTFAST32_NUMBITS (8 * sizeof(uint_fast32_t))
+
 #ifdef __cplusplus
 extern "C" {
 #endif
```
