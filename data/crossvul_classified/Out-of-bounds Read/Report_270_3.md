# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 270_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `270_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 58-98 of the vulnerable file.



#define ReadOK(file, buffer, len) \
  (JFREAD(file, buffer, len) == ((size_t)(len)))

static int alpha_index[JPEG_NUMCS] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3, 3, 0, 0, -1
};


/* Private version of data source object */

typedef struct {
  struct cjpeg_source_struct pub; /* public fields */

  /* Usually these two pointers point to the same place: */
  U_CHAR *iobuffer;             /* fread's I/O buffer */
  JSAMPROW pixrow;              /* compressor input buffer */
  size_t buffer_width;          /* width of I/O buffer */
  JSAMPLE *rescale;             /* => maxval-remapping array, or NULL */
  int maxval;
} ppm_source_struct;

typedef ppm_source_struct *ppm_source_ptr;


LOCAL(int)
pbm_getc(FILE *infile)
/* Read next char, skipping over any comments */
/* A comment/newline sequence is returned as a newline */
{
  register int ch;

  ch = getc(infile);
  if (ch == '#') {
    do {
      ch = getc(infile);
    } while (ch != '\n' && ch != EOF);
  }
  return ch;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,7 +75,7 @@
   JSAMPROW pixrow;              /* compressor input buffer */
   size_t buffer_width;          /* width of I/O buffer */
   JSAMPLE *rescale;             /* => maxval-remapping array, or NULL */
-  int maxval;
+  unsigned int maxval;
 } ppm_source_struct;
 
 typedef ppm_source_struct *ppm_source_ptr;
@@ -125,7 +125,7 @@
   }
 
   if (val > maxval)
-    ERREXIT(cinfo, JERR_PPM_TOOLARGE);
+    ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);
 
   return val;
 }
@@ -509,7 +509,7 @@
     temp  = UCH(*bufferptr++) << 8;
     temp |= UCH(*bufferptr++);
     if (temp > maxval)
-      ERREXIT(cinfo, JERR_PPM_TOOLARGE);
+      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);
     *ptr++ = rescale[temp];
   }
   return 1;
@@ -536,17 +536,17 @@
     temp  = UCH(*bufferptr++) << 8;
     temp |= UCH(*bufferptr++);
     if (temp > maxval)
-      ERREXIT(cinfo, JERR_PPM_TOOLARGE);
+      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);
     *ptr++ = rescale[temp];
     temp  = UCH(*bufferptr++) << 8;
     temp |= UCH(*bufferptr++);
     if (temp > maxval)
-      ERREXIT(cinfo, JERR_PPM_TOOLARGE);
+      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);
     *ptr++ = rescale[temp];
     temp  = UCH(*bufferptr++) << 8;
     temp |= UCH(*bufferptr++);
     if (temp > maxval)
-      ERREXIT(cinfo, JERR_PPM_TOOLARGE);
+      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);
     *ptr++ = rescale[temp];
   }
   return 1;
```
