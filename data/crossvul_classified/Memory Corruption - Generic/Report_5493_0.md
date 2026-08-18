# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5493_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5493_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 75-115 of the vulnerable file.

    (defined(__WATCOMC__) && defined(__386__)) || \
    (defined(__POCC__) && defined(_MSC_VER)) || \
    (defined(_WIN32_WCE)) || \
    (defined(__MINGW32__)) || \
    (defined(_MSC_VER) && (_MSC_VER >= 900) && (_INTEGRAL_MAX_BITS >= 64))
#  define MP_HAVE_INT_EXTENSIONS
#endif

/*
 * Max integer data types that mprintf.c is capable
 */

#ifdef HAVE_LONG_LONG_TYPE
#  define mp_intmax_t LONG_LONG_TYPE
#  define mp_uintmax_t unsigned LONG_LONG_TYPE
#else
#  define mp_intmax_t long
#  define mp_uintmax_t unsigned long
#endif

#define BUFFSIZE 256 /* buffer for long-to-str and float-to-str calcs */
#define MAX_PARAMETERS 128 /* lame static limit */

#ifdef __AMIGA__
# undef FORMAT_INT
#endif

/* Lower-case digits.  */
static const char lower_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";

/* Upper-case digits.  */
static const char upper_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define OUTCHAR(x) \
  do{ \
    if(stream((unsigned char)(x), (FILE *)data) != -1) \
      done++; \
    else \
     return done; /* return immediately on failure */ \
  } WHILE_FALSE

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,7 +92,8 @@
 #  define mp_uintmax_t unsigned long
 #endif
 
-#define BUFFSIZE 256 /* buffer for long-to-str and float-to-str calcs */
+#define BUFFSIZE 326 /* buffer for long-to-str and float-to-str calcs, should
+                        fit negative DBL_MAX (317 letters) */
 #define MAX_PARAMETERS 128 /* lame static limit */
 
 #ifdef __AMIGA__
@@ -916,12 +917,25 @@
         *fptr = 0;
 
         if(width >= 0) {
+          if(width >= (long)sizeof(work))
+            width = sizeof(work)-1;
           /* RECURSIVE USAGE */
           len = curl_msnprintf(fptr, left, "%ld", width);
           fptr += len;
           left -= len;
         }
         if(prec >= 0) {
+          /* for each digit in the integer part, we can have one less
+             precision */
+          size_t maxprec = sizeof(work) - 2;
+          double val = p->data.dnum;
+          while(val >= 10.0) {
+            val /= 10;
+            maxprec--;
+          }
+
+          if(prec > (long)maxprec)
+            prec = maxprec-1;
           /* RECURSIVE USAGE */
           len = curl_msnprintf(fptr, left, ".%ld", prec);
           fptr += len;
@@ -941,7 +955,9 @@
         /* NOTE NOTE NOTE!! Not all sprintf implementations return number of
            output characters */
         (sprintf)(work, formatbuf, p->data.dnum);
-
+#ifdef CURLDEBUG
+        assert(strlen(work) <= sizeof(work));
+#endif
         for(fptr=work; *fptr; fptr++)
           OUTCHAR(*fptr);
       }
```
