# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 523_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `523_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 71-111 of the vulnerable file.

#define DEBUGPROTO(x)
#endif
#include <stdarg.h>
#include <scale.h>
/* stst() */
#include <sys/types.h>
#include <sys/stat.h>
#if LIBVNCSERVER_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef WIN32
/* readdir() */
#include <dirent.h>
#endif

/* errno */
#include <errno.h>
/* strftime() */
#include <time.h>

#ifdef LIBVNCSERVER_WITH_WEBSOCKETS
#include "rfbssl.h"
#endif

#ifdef _MSC_VER
#define snprintf _snprintf /* Missing in MSVC */
/* Prevent POSIX deprecation warnings */
#define close _close
#define strdup _strdup 
#endif

#ifdef WIN32
#include <direct.h>
#ifdef __MINGW32__
#define mkdir(path, perms) mkdir(path) /* Omit the perms argument to match POSIX signature */
#else /* MSVC and other windows compilers */
#define mkdir(path, perms) _mkdir(path) /* Omit the perms argument to match POSIX signature */
#endif /* __MINGW32__ else... */
#ifndef S_ISDIR
#define S_ISDIR(m)	(((m) & S_IFDIR) == S_IFDIR)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,6 +88,8 @@
 #include <errno.h>
 /* strftime() */
 #include <time.h>
+/* INT_MAX */
+#include <limits.h>
 
 #ifdef LIBVNCSERVER_WITH_WEBSOCKETS
 #include "rfbssl.h"
@@ -1472,8 +1474,11 @@
        0XFFFFFFFF, i.e. SIZE_MAX for 32-bit systems. On 64-bit systems, a length of 0XFFFFFFFF
        will safely be allocated since this check will never trigger and malloc() can digest length+1
        without problems as length is a uint32_t.
+       We also later pass length to rfbReadExact() that expects a signed int type and
+       that might wrap on platforms with a 32-bit int type if length is bigger
+       than 0X7FFFFFFF.
     */
-    if(length == SIZE_MAX) {
+    if(length == SIZE_MAX || length > INT_MAX) {
 	rfbErr("rfbProcessFileTransferReadBuffer: too big file transfer length requested: %u", (unsigned int)length);
 	rfbCloseClient(cl);
 	return NULL;
```
