# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 1321_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1321_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* NetHack 3.6	files.c	$NHDT-Date: 1574116097 2019/11/18 22:28:17 $  $NHDT-Branch: NetHack-3.6 $:$NHDT-Revision: 1.272 $ */
/* Copyright (c) Stichting Mathematisch Centrum, Amsterdam, 1985. */
/*-Copyright (c) Derek S. Ray, 2015. */
/* NetHack may be freely redistributed.  See license for details. */

#define NEED_VARARGS

#include "hack.h"
#include "dlb.h"

#ifdef TTY_GRAPHICS
#include "wintty.h" /* more() */
#endif

#if (!defined(MAC) && !defined(O_WRONLY) && !defined(AZTEC_C)) \
    || defined(USE_FCNTL)
#include <fcntl.h>
#endif

#include <errno.h>
#ifdef _MSC_VER /* MSC 6.0 defines errno quite differently */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* NetHack 3.6	files.c	$NHDT-Date: 1574116097 2019/11/18 22:28:17 $  $NHDT-Branch: NetHack-3.6 $:$NHDT-Revision: 1.272 $ */
+/* NetHack 3.6	files.c	$NHDT-Date: 1576626110 2019/12/17 23:41:50 $  $NHDT-Branch: NetHack-3.6 $:$NHDT-Revision: 1.276 $ */
 /* Copyright (c) Stichting Mathematisch Centrum, Amsterdam, 1985. */
 /*-Copyright (c) Derek S. Ray, 2015. */
 /* NetHack may be freely redistributed.  See license for details. */
@@ -3160,7 +3160,8 @@
                         free(buf);
                     }
                     buf = strcat(tmpbuf, ep);
-                    buf[sizeof inbuf - 1] = '\0';
+                    if (strlen(buf) >= sizeof inbuf)
+                        buf[sizeof inbuf - 1] = '\0';
                 }
 
                 if (morelines || (ignoreline && !oldline))
```
