# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 651_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `651_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1050-1077 of the vulnerable file.

 * Gets SHA-1 of input buffer
 */
void gf_sha1_csum(u8 *buf, u32 buflen, u8 digest[GF_SHA1_DIGEST_SIZE]);
/*
 * Gets SHA-1 of input buffer into hexa form
 */
void gf_sha1_csum_hexa(u8 *buf, u32 buflen, u8 digest[GF_SHA1_DIGEST_SIZE_HEXA]);

/*! @} */


/* \cond dummy */
#ifdef GPAC_ANDROID
typedef void (*fm_callback_func)(void *cbk_obj, u32 type, u32 param, int *value);
extern void gf_fm_request_set_callback(void *cbk_obj, fm_callback_func cbk_func);
void gf_fm_request_call(u32 type, u32 param, int *value);
#endif //GPAC_ANDROID

/* \endcond */


#ifdef __cplusplus
}
#endif


#endif		/*_GF_CORE_H_*/

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1067,6 +1067,7 @@
 
 /* \endcond */
 
+#define ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))
 
 #ifdef __cplusplus
 }
```
