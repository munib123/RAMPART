# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 5319_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5319_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 53-93 of the vulnerable file.

#include "magick/exception-private.h"
#include "magick/image.h"
#include "magick/image-private.h"
#include "magick/list.h"
#include "magick/magick.h"
#include "magick/memory_.h"
#include "magick/monitor.h"
#include "magick/monitor-private.h"
#include "magick/pixel-accessor.h"
#include "magick/quantum-private.h"
#include "magick/static.h"
#include "magick/string_.h"
#include "magick/module.h"
#include "magick/utility.h"


/*
  Forward declarations.
*/
static MagickBooleanType
  WriteRGFImage(const ImageInfo *,Image *,ExceptionInfo *);


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   R e a d X B M I m a g e                                                   %
%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  ReadRGFImage() reads an RGF bitmap image file and returns it.  It
%  allocates the memory necessary for the new Image structure and returns a
%  pointer to the new image.
%
%  The format of the ReadRGFImage method is:
%
%      Image *ReadRGFImage(const ImageInfo *image_info,ExceptionInfo *exception)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,7 +70,7 @@
   Forward declarations.
 */
 static MagickBooleanType
-  WriteRGFImage(const ImageInfo *,Image *,ExceptionInfo *);
+  WriteRGFImage(const ImageInfo *,Image *);
 
 
 /*
@@ -311,7 +311,7 @@
 %  The format of the WriteRGFImage method is:
 %
 %      MagickBooleanType WriteRGFImage(const ImageInfo *image_info,
-%        Image *image,ExceptionInfo *exception)
+%        Image *image)
 %
 %  A description of each parameter follows.
 %
@@ -322,8 +322,7 @@
 %    o exception: return any errors or warnings in this structure.
 %
 */
-static MagickBooleanType WriteRGFImage(const ImageInfo *image_info,Image *image,
-  ExceptionInfo *exception)
+static MagickBooleanType WriteRGFImage(const ImageInfo *image_info,Image *image)
 {
   MagickBooleanType
     status;
@@ -352,9 +351,7 @@
   assert(image->signature == MagickSignature);
   if (image->debug != MagickFalse)
     (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
-  assert(exception != (ExceptionInfo *) NULL);
-  assert(exception->signature == MagickSignature);
-  status=OpenBlob(image_info,image,WriteBinaryBlobMode,exception);
+  status=OpenBlob(image_info,image,WriteBinaryBlobMode,&image->exception);
   if (status == MagickFalse)
     return(status);
   (void) TransformImageColorspace(image,sRGBColorspace);
@@ -373,7 +370,7 @@
   y=0;
   for (y=0; y < (ssize_t) image->rows; y++)
   {
-    p=GetVirtualPixels(image,0,y,image->columns,1,exception);
+    p=GetVirtualPixels(image,0,y,image->columns,1,&image->exception);
     if (p == (const PixelPacket *) NULL)
       break;
     bit=0;
```
