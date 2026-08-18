# CrossVul Fix Pair: Incorrect Type Conversion or Cast in c
**Pair ID:** 579_3
**Vulnerability Class:** Type Confusion
**CWE:** CWE-704
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `579_3`)

## Vulnerability Information & PoC

## Description
Incorrect Type Conversion or Cast - The product does not correctly convert an object, resource, or structure from one type to a different type.

## Vulnerable Code
```c
Lines 5-45 of the vulnerable file.

 *
 * LibRaw C++ interface
 *

LibRaw is free software; you can redistribute it and/or modify
it under the terms of the one of two licenses as you choose:

1. GNU LESSER GENERAL PUBLIC LICENSE version 2.1
(See the file LICENSE.LGPL provided in LibRaw distribution archive for details).

2. COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) Version 1.0
(See the file LICENSE.CDDL provided in LibRaw distribution archive for details).

 */

#ifndef __VERSION_H
#define __VERSION_H

#define LIBRAW_MAJOR_VERSION  0
#define LIBRAW_MINOR_VERSION  18
#define LIBRAW_PATCH_VERSION  7
#define LIBRAW_VERSION_TAIL   Release

#define LIBRAW_SHLIB_CURRENT  	16
#define LIBRAW_SHLIB_REVISION 	0
#define LIBRAW_SHLIB_AGE     	0

#define _LIBRAW_VERSION_MAKE(a,b,c,d) #a"."#b"."#c"-"#d
#define LIBRAW_VERSION_MAKE(a,b,c,d) _LIBRAW_VERSION_MAKE(a,b,c,d)

#define LIBRAW_VERSION_STR LIBRAW_VERSION_MAKE(LIBRAW_MAJOR_VERSION,LIBRAW_MINOR_VERSION,LIBRAW_PATCH_VERSION,LIBRAW_VERSION_TAIL)

#define LIBRAW_MAKE_VERSION(major,minor,patch) \
    (((major) << 16) | ((minor) << 8) | (patch))

#define LIBRAW_VERSION \
    LIBRAW_MAKE_VERSION(LIBRAW_MAJOR_VERSION,LIBRAW_MINOR_VERSION,LIBRAW_PATCH_VERSION)

#define LIBRAW_CHECK_VERSION(major,minor,patch) \
    ( LibRaw::versionNumber() >= LIBRAW_MAKE_VERSION(major,minor,patch) )

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,7 +22,7 @@
 
 #define LIBRAW_MAJOR_VERSION  0
 #define LIBRAW_MINOR_VERSION  18
-#define LIBRAW_PATCH_VERSION  7
+#define LIBRAW_PATCH_VERSION  8
 #define LIBRAW_VERSION_TAIL   Release
 
 #define LIBRAW_SHLIB_CURRENT  	16
```
