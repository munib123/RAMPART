# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 270_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `270_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-25 of the vulnerable file.

/*
 * cderror.h
 *
 * Copyright (C) 1994-1997, Thomas G. Lane.
 * Modified 2009 by Guido Vollbeding.
 * This file is part of the Independent JPEG Group's software.
 * For conditions of distribution and use, see the accompanying README.ijg
 * file.
 *
 * This file defines the error and message codes for the cjpeg/djpeg
 * applications.  These strings are not needed as part of the JPEG library
 * proper.
 * Edit this file to add new codes, or to translate the message strings to
 * some other language.
 */

/*
 * To define the enum list of message codes, include this file without
 * defining macro JMESSAGE.  To create a message string table, include it
 * again with a suitable JMESSAGE definition (see jerror.c for an example).
 */
#ifndef JMESSAGE
#ifndef CDERROR_H
#define CDERROR_H
/* First time through, define the enum list */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
  * cderror.h
  *
  * Copyright (C) 1994-1997, Thomas G. Lane.
- * Modified 2009 by Guido Vollbeding.
+ * Modified 2009-2017 by Guido Vollbeding.
  * This file is part of the Independent JPEG Group's software.
  * For conditions of distribution and use, see the accompanying README.ijg
  * file.
@@ -49,6 +49,7 @@
 JMESSAGE(JERR_BMP_COMPRESSED, "Sorry, compressed BMPs not yet supported")
 JMESSAGE(JERR_BMP_EMPTY, "Empty BMP image")
 JMESSAGE(JERR_BMP_NOT, "Not a BMP file - does not start with BM")
+JMESSAGE(JERR_BMP_OUTOFRANGE, "Numeric value out of range in BMP file")
 JMESSAGE(JTRC_BMP, "%ux%u 24-bit BMP image")
 JMESSAGE(JTRC_BMP_MAPPED, "%ux%u 8-bit colormapped BMP image")
 JMESSAGE(JTRC_BMP_OS2, "%ux%u 24-bit OS2 BMP image")
@@ -75,8 +76,8 @@
 #ifdef PPM_SUPPORTED
 JMESSAGE(JERR_PPM_COLORSPACE, "PPM output must be grayscale or RGB")
 JMESSAGE(JERR_PPM_NONNUMERIC, "Nonnumeric data in PPM file")
-JMESSAGE(JERR_PPM_TOOLARGE, "Integer value too large in PPM file")
 JMESSAGE(JERR_PPM_NOT, "Not a PPM/PGM file")
+JMESSAGE(JERR_PPM_OUTOFRANGE, "Numeric value out of range in PPM file")
 JMESSAGE(JTRC_PGM, "%ux%u PGM image")
 JMESSAGE(JTRC_PGM_TEXT, "%ux%u text PGM image")
 JMESSAGE(JTRC_PPM, "%ux%u PPM image")
```
