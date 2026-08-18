# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3365_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3365_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 118-158 of the vulnerable file.

%  The format of the ReadRLEImage method is:
%
%      Image *ReadRLEImage(const ImageInfo *image_info,ExceptionInfo *exception)
%
%  A description of each parameter follows:
%
%    o image_info: the image info.
%
%    o exception: return any errors or warnings in this structure.
%
%
*/
static Image *ReadRLEImage(const ImageInfo *image_info,ExceptionInfo *exception)
{
#define SkipLinesOp  0x01
#define SetColorOp  0x02
#define SkipPixelsOp  0x03
#define ByteDataOp  0x05
#define RunDataOp  0x06
#define EOFOp  0x07

  char
    magick[12];

  Image
    *image;

  IndexPacket
    index;

  int
    opcode,
    operand,
    status;

  MagickStatusType
    flags;

  MagickSizeType
    number_pixels;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -135,6 +135,15 @@
 #define ByteDataOp  0x05
 #define RunDataOp  0x06
 #define EOFOp  0x07
+#define ThrowRLEException(exception,message) \
+{ \
+  if (colormap != (unsigned char *) NULL) \
+    colormap=(unsigned char *) RelinquishMagickMemory(colormap); \
+  if (pixel_info != (MemoryInfo *) NULL) \
+    pixel_info=RelinquishVirtualMemory(pixel_info); \
+  ThrowReaderException((exception),(message)); \
+}
+
 
   char
     magick[12];
@@ -212,6 +221,8 @@
   /*
     Determine if this a RLE file.
   */
+  colormap=(unsigned char *) NULL;
+  pixel_info=(MemoryInfo *) NULL;
   count=ReadBlob(image,2,(unsigned char *) magick);
   if ((count != 2) || (memcmp(magick,"\122\314",2) != 0))
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
@@ -220,8 +231,8 @@
     /*
       Read image header.
     */
-    image->page.x=ReadBlobLSBShort(image);
-    image->page.y=ReadBlobLSBShort(image);
+    image->page.x=(ssize_t) ReadBlobLSBShort(image);
+    image->page.y=(ssize_t) ReadBlobLSBShort(image);
     image->columns=ReadBlobLSBShort(image);
     image->rows=ReadBlobLSBShort(image);
     flags=(MagickStatusType) ReadBlobByte(image);
@@ -232,6 +243,8 @@
     map_length=(unsigned char) ReadBlobByte(image);
     if (map_length >= 22)
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+    if (EOFBlob(image) != MagickFalse)
+      ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
     one=1;
     map_length=one << map_length;
     if ((number_planes == 0) || (number_planes == 2) ||
@@ -259,11 +272,7 @@
     if ((number_planes & 0x01) == 0)
       (void) ReadBlobByte(image);
     if (EOFBlob(image) != MagickFalse)
-      {
-        ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
-          image->filename);
-        break;
-      }
+      ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
     colormap=(unsigned char *) NULL;
     if (number_colormaps != 0)
       {
@@ -277,8 +286,12 @@
         p=colormap;
         for (i=0; i < (ssize_t) number_colormaps; i++)
           for (x=0; x < (ssize_t) map_length; x++)
+          {
             *p++=(unsigned char) ScaleQuantumToChar(ScaleShortToQuantum(
               ReadBlobLSBShort(image)));
+            if (EOFBlob(image) != MagickFalse)
+              ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
+          }
       }
     if ((flags & 0x08) != 0)
       {
@@ -306,11 +319,7 @@
           }
       }
     if (EOFBlob(image) != MagickFalse)
-      {
-        ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
-          image->filename);
-        break;
-      }
+      ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
@@ -368,6 +377,8 @@
     x=0;
     y=0;
     opcode=ReadBlobByte(image);
+    if (opcode == EOF)
+      ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
     do
     {
       switch (opcode & 0x3f)
@@ -375,8 +386,14 @@
         case SkipLinesOp:
         {
           operand=ReadBlobByte(image);
+          if (opcode == EOF)
+            ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
           if (opcode & 0x40)
-            operand=ReadBlobLSBSignedShort(image);
+            {
+              operand=ReadBlobLSBSignedShort(image);
+              if (opcode == EOF)
+                ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
+            }
           x=0;
           y+=operand;
           break;
@@ -384,6 +401,8 @@
         case SetColorOp:
         {
           operand=ReadBlobByte(image);
+          if (opcode == EOF)
+            ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
           plane=(unsigned char) operand;
           if (plane == 255)
             plane=(unsigned char) (number_planes-1);
@@ -393,21 +412,33 @@
         case SkipPixelsOp:
         {
           operand=ReadBlobByte(image);
+          if (opcode == EOF)
+            ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
           if (opcode & 0x40)
-            operand=ReadBlobLSBSignedShort(image);
+            {
+              operand=ReadBlobLSBSignedShort(image);
+              if (opcode == EOF)
+                ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
+            }
           x+=operand;
           break;
         }
         case ByteDataOp:
         {
           operand=ReadBlobByte(image);
+          if (opcode == EOF)
+            ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
           if (opcode & 0x40)
-            operand=ReadBlobLSBSignedShort(image);
-          offset=((image->rows-y-1)*image->columns*number_planes)+x*
-            number_planes+plane;
+            {
+              operand=ReadBlobLSBSignedShort(image);
+              if (opcode == EOF)
+                ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
+            }
+          offset=(ssize_t) (((image->rows-y-1)*image->columns*number_planes)+x*
+            number_planes+plane);
           operand++;
           if ((offset < 0) ||
-              (offset+((size_t) operand*number_planes) > pixel_info_length))
+              ((offset+operand*number_planes) > (ssize_t) pixel_info_length))
             {
               if (number_colormaps != 0)
                 colormap=(unsigned char *) RelinquishMagickMemory(colormap);
@@ -431,15 +462,21 @@
         case RunDataOp:
         {
           operand=ReadBlobByte(image);
+          if (opcode == EOF)
+            ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
           if (opcode & 0x40)
-            operand=ReadBlobLSBSignedShort(image);
+            {
+              operand=ReadBlobLSBSignedShort(image);
+              if (opcode == EOF)
+                ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
+            }
           pixel=(unsigned char) ReadBlobByte(image);
           (void) ReadBlobByte(image);
           operand++;
-          offset=((image->rows-y-1)*image->columns*number_planes)+x*
-            number_planes+plane;
+          offset=(ssize_t) (((image->rows-y-1)*image->columns*number_planes)+x*
+            number_planes+plane);
           if ((offset < 0) ||
-              (offset+((size_t) operand*number_planes) > pixel_info_length))
+              ((offset+operand*number_planes) > (ssize_t) pixel_info_length))
             {
               if (number_colormaps != 0)
                 colormap=(unsigned char *) RelinquishMagickMemory(colormap);
@@ -461,6 +498,8 @@
           break;
       }
       opcode=ReadBlobByte(image);
+      if (opcode == EOF)
+        ThrowRLEException(CorruptImageError,"UnexpectedEndOfFile");
     } while (((opcode & 0x3f) != EOFOp) && (opcode != EOF));
     if (number_colormaps != 0)
       {
@@ -476,7 +515,7 @@
         if (number_colormaps == 1)
           for (i=0; i < (ssize_t) number_pixels; i++)
           {
-            if (IsValidColormapIndex(image,*p & mask,&index,exception) ==
+            if (IsValidColormapIndex(image,(ssize_t) (*p & mask),&index,exception) ==
                 MagickFalse)
               break;
             *p=colormap[(ssize_t) index];
@@ -487,7 +526,7 @@
             for (i=0; i < (ssize_t) number_pixels; i++)
               for (x=0; x < (ssize_t) number_planes; x++)
               {
-                if (IsValidColormapIndex(image,(size_t) (x*map_length+
+                if (IsValidColormapIndex(image,(ssize_t) (x*map_length+
                     (*p & mask)),&index,exception) == MagickFalse)
                   break;
                 *p=colormap[(ssize_t) index];
@@ -601,15 +640,15 @@
                 break;
               for (x=0; x < (ssize_t) image->columns; x++)
               {
-                if (IsValidColormapIndex(image,*p++,&index,exception) ==
... (diff truncated)
```
