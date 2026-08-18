# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1221_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1221_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 49-89 of the vulnerable file.

#include "MagickCore/blob-private.h"
#include "MagickCore/cache.h"
#include "MagickCore/constitute.h"
#include "MagickCore/composite-private.h"
#include "MagickCore/delegate.h"
#include "MagickCore/delegate-private.h"
#include "MagickCore/draw.h"
#include "MagickCore/exception.h"
#include "MagickCore/exception-private.h"
#include "MagickCore/gem.h"
#include "MagickCore/image.h"
#include "MagickCore/image-private.h"
#include "MagickCore/list.h"
#include "MagickCore/log.h"
#include "MagickCore/magick.h"
#include "MagickCore/memory_.h"
#include "MagickCore/memory-private.h"
#include "MagickCore/module.h"
#include "MagickCore/monitor.h"
#include "MagickCore/monitor-private.h"
#include "MagickCore/quantum-private.h"
#include "MagickCore/pixel-accessor.h"
#include "MagickCore/property.h"
#include "MagickCore/resource_.h"
#include "MagickCore/static.h"
#include "MagickCore/string_.h"
#include "MagickCore/string-private.h"
#include "MagickCore/token.h"
#include "MagickCore/utility.h"

#if defined(MAGICKCORE_XML_DELEGATE)
#  if defined(MAGICKCORE_WINDOWS_SUPPORT)
#    if !defined(__MINGW32__)
#      include <win32config.h>
#    endif
#  endif
#  include <libxml/xmlmemory.h>
#  include <libxml/parserInternals.h>
#  include <libxml/xmlerror.h>
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -66,9 +66,10 @@
 #include "MagickCore/module.h"
 #include "MagickCore/monitor.h"
 #include "MagickCore/monitor-private.h"
-#include "MagickCore/quantum-private.h"
+#include "MagickCore/option.h"
 #include "MagickCore/pixel-accessor.h"
 #include "MagickCore/property.h"
+#include "MagickCore/quantum-private.h"
 #include "MagickCore/resource_.h"
 #include "MagickCore/static.h"
 #include "MagickCore/string_.h"
@@ -3586,9 +3587,14 @@
   message[n]='\0';
   if (n > 0)
     {
+      const char
+        *value;
+
       svg_info->parser=xmlCreatePushParserCtxt(sax_handler,svg_info,(char *)
         message,n,image->filename);
-      (void) xmlCtxtUseOptions(svg_info->parser,XML_PARSE_HUGE);
+      value=GetImageOption(image_info,"svg:xml-parse-huge");
+      if ((value != (char *) NULL) && (IsStringTrue(value) != MagickFalse))
+        (void) xmlCtxtUseOptions(svg_info->parser,XML_PARSE_HUGE);
       while ((n=ReadBlob(image,MagickPathExtent-1,message)) != 0)
       {
         message[n]='\0';
```
