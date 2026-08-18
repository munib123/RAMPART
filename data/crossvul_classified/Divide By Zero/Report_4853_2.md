# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 4853_2
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4853_2`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 233-273 of the vulnerable file.

/*
 * Default Read/Seek/Write definitions.
 */
#ifndef ReadOK
#define ReadOK(tif, buf, size) \
	(TIFFReadFile((tif),(buf),(size))==(size))
#endif
#ifndef SeekOK
#define SeekOK(tif, off) \
	(TIFFSeekFile((tif),(off),SEEK_SET)==(off))
#endif
#ifndef WriteOK
#define WriteOK(tif, buf, size) \
	(TIFFWriteFile((tif),(buf),(size))==(size))
#endif

/* NB: the uint32 casts are to silence certain ANSI-C compilers */
#define TIFFhowmany_32(x, y) (((uint32)x < (0xffffffff - (uint32)(y-1))) ? \
			   ((((uint32)(x))+(((uint32)(y))-1))/((uint32)(y))) : \
			   0U)
#define TIFFhowmany8_32(x) (((x)&0x07)?((uint32)(x)>>3)+1:(uint32)(x)>>3)
#define TIFFroundup_32(x, y) (TIFFhowmany_32(x,y)*(y))
#define TIFFhowmany_64(x, y) ((((uint64)(x))+(((uint64)(y))-1))/((uint64)(y)))
#define TIFFhowmany8_64(x) (((x)&0x07)?((uint64)(x)>>3)+1:(uint64)(x)>>3)
#define TIFFroundup_64(x, y) (TIFFhowmany_64(x,y)*(y))

/* Safe multiply which returns zero if there is an integer overflow */
#define TIFFSafeMultiply(t,v,m) ((((t)(m) != (t)0) && (((t)(((v)*(m))/(m))) == (t)(v))) ? (t)((v)*(m)) : (t)0)

#define TIFFmax(A,B) ((A)>(B)?(A):(B))
#define TIFFmin(A,B) ((A)<(B)?(A):(B))

#define TIFFArrayCount(a) (sizeof (a) / sizeof ((a)[0]))

/*
  Support for large files.

  Windows read/write APIs support only 'unsigned int' rather than 'size_t'.
  Windows off_t is only 32-bit, even in 64-bit builds.
*/
#if defined(HAVE_FSEEKO)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -250,6 +250,10 @@
 #define TIFFhowmany_32(x, y) (((uint32)x < (0xffffffff - (uint32)(y-1))) ? \
 			   ((((uint32)(x))+(((uint32)(y))-1))/((uint32)(y))) : \
 			   0U)
+/* Variant of TIFFhowmany_32() that doesn't return 0 if x close to MAXUINT. */
+/* Caution: TIFFhowmany_32_maxuint_compat(x,y)*y might overflow */
+#define TIFFhowmany_32_maxuint_compat(x, y) \
+			   (((uint32)(x) / (uint32)(y)) + ((((uint32)(x) % (uint32)(y)) != 0) ? 1 : 0))
 #define TIFFhowmany8_32(x) (((x)&0x07)?((uint32)(x)>>3)+1:(uint32)(x)>>3)
 #define TIFFroundup_32(x, y) (TIFFhowmany_32(x,y)*(y))
 #define TIFFhowmany_64(x, y) ((((uint64)(x))+(((uint64)(y))-1))/((uint64)(y)))
```
