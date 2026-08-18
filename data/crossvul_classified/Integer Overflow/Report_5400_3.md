# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5400_3
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5400_3`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 90-114 of the vulnerable file.

  level is set sufficiently high. */
#if !defined(NDEBUG)
#define	JAS_DBGLOG(n, x) \
	((jas_getdbglevel() >= (n)) ? (jas_eprintf x) : 0)
#else
#define	JAS_DBGLOG(n, x)
#endif

/* Get the library debug level. */
int jas_getdbglevel(void);

/* Set the library debug level. */
int jas_setdbglevel(int dbglevel);

/* Perform formatted output to standard error. */
int jas_eprintf(const char *fmt, ...);

/* Dump memory to a stream. */
int jas_memdump(FILE *out, void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,6 +107,9 @@
 /* Dump memory to a stream. */
 int jas_memdump(FILE *out, void *data, size_t len);
 
+/* Warn about use of deprecated functionality. */
+void jas_deprecated(const char *s);
+
 #ifdef __cplusplus
 }
 #endif
```
