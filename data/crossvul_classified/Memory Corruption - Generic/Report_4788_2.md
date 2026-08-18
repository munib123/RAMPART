# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4788_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4788_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 35-75 of the vulnerable file.

%
%
%
*/


/*
  Include declarations.
*/
#include "magick/studio.h"
#include "magick/client.h"
#include "magick/exception.h"
#include "magick/exception-private.h"
#include "magick/hashmap.h"
#include "magick/locale_.h"
#include "magick/log.h"
#include "magick/magick.h"
#include "magick/memory_.h"
#include "magick/string_.h"
#include "magick/utility.h"


/*
  Forward declarations.
*/
#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

static void
  DefaultErrorHandler(const ExceptionType,const char *,const char *),
  DefaultFatalErrorHandler(const ExceptionType,const char *,const char *),
  DefaultWarningHandler(const ExceptionType,const char *,const char *);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif


/*
  Global declarations.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,6 +52,12 @@
 #include "magick/memory_.h"
 #include "magick/string_.h"
 #include "magick/utility.h"
+
+
+/*
+  Global declarations.
+*/
+#define MaxExceptions  128
 
 
 /*
@@ -199,6 +205,9 @@
   register const ExceptionInfo
     *p;
 
+  ssize_t
+    i;
+
   assert(exception != (ExceptionInfo *) NULL);
   assert(exception->signature == MagickSignature);
   if (exception->exceptions  == (void *) NULL)
@@ -207,14 +216,22 @@
   ResetLinkedListIterator((LinkedListInfo *) exception->exceptions);
   p=(const ExceptionInfo *) GetNextValueInLinkedList((LinkedListInfo *)
     exception->exceptions);
-  while (p != (const ExceptionInfo *) NULL)
+  for (i=0; p != (const ExceptionInfo *) NULL; i++)
   {
-    if ((p->severity >= WarningException) && (p->severity < ErrorException))
-      MagickWarning(p->severity,p->reason,p->description);
-    if ((p->severity >= ErrorException) && (p->severity < FatalErrorException))
-      MagickError(p->severity,p->reason,p->description);
     if (p->severity >= FatalErrorException)
       MagickFatalError(p->severity,p->reason,p->description);
+    if (i < MaxExceptions)
+      {
+        if ((p->severity >= ErrorException) && 
+            (p->severity < FatalErrorException))
+          MagickError(p->severity,p->reason,p->description);
+        if ((p->severity >= WarningException) && (p->severity < ErrorException))
+          MagickWarning(p->severity,p->reason,p->description);
+      }
+    else
+      if (i == MaxExceptions)
+        MagickError(ResourceLimitError,"too many exceptions",
+          "exception processing suspended");
     p=(const ExceptionInfo *) GetNextValueInLinkedList((LinkedListInfo *)
       exception->exceptions);
   }
```
