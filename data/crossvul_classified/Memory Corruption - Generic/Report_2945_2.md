# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2945_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2945_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 214-254 of the vulnerable file.

  LIBRAW_OPIONS_NO_MEMERR_CALLBACK = 1,
  LIBRAW_OPIONS_NO_DATAERR_CALLBACK = 1 << 1
};

enum LibRaw_warnings
{
  LIBRAW_WARN_NONE = 0,
  LIBRAW_WARN_BAD_CAMERA_WB = 1 << 2,
  LIBRAW_WARN_NO_METADATA = 1 << 3,
  LIBRAW_WARN_NO_JPEGLIB = 1 << 4,
  LIBRAW_WARN_NO_EMBEDDED_PROFILE = 1 << 5,
  LIBRAW_WARN_NO_INPUT_PROFILE = 1 << 6,
  LIBRAW_WARN_BAD_OUTPUT_PROFILE = 1 << 7,
  LIBRAW_WARN_NO_BADPIXELMAP = 1 << 8,
  LIBRAW_WARN_BAD_DARKFRAME_FILE = 1 << 9,
  LIBRAW_WARN_BAD_DARKFRAME_DIM = 1 << 10,
  LIBRAW_WARN_NO_JASPER = 1 << 11,
  LIBRAW_WARN_RAWSPEED_PROBLEM = 1 << 12,
  LIBRAW_WARN_RAWSPEED_UNSUPPORTED = 1 << 13,
  LIBRAW_WARN_RAWSPEED_PROCESSED = 1 << 14,
  LIBRAW_WARN_FALLBACK_TO_AHD = 1 << 15
};

enum LibRaw_exceptions
{
  LIBRAW_EXCEPTION_NONE = 0,
  LIBRAW_EXCEPTION_ALLOC = 1,
  LIBRAW_EXCEPTION_DECODE_RAW = 2,
  LIBRAW_EXCEPTION_DECODE_JPEG = 3,
  LIBRAW_EXCEPTION_IO_EOF = 4,
  LIBRAW_EXCEPTION_IO_CORRUPT = 5,
  LIBRAW_EXCEPTION_CANCELLED_BY_CALLBACK = 6,
  LIBRAW_EXCEPTION_BAD_CROP = 7,
  LIBRAW_EXCEPTION_IO_BADFILE = 8,
  LIBRAW_EXCEPTION_DECODE_JPEG2000 = 9
};

enum LibRaw_progress
{
  LIBRAW_PROGRESS_START = 0,
  LIBRAW_PROGRESS_OPEN = 1,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -231,7 +231,8 @@
   LIBRAW_WARN_RAWSPEED_PROBLEM = 1 << 12,
   LIBRAW_WARN_RAWSPEED_UNSUPPORTED = 1 << 13,
   LIBRAW_WARN_RAWSPEED_PROCESSED = 1 << 14,
-  LIBRAW_WARN_FALLBACK_TO_AHD = 1 << 15
+  LIBRAW_WARN_FALLBACK_TO_AHD = 1 << 15,
+  LIBRAW_WARN_PARSEFUJI_PROCESSED = 1 << 16
 };
 
 enum LibRaw_exceptions
```
