# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2785_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2785_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 118-158 of the vulnerable file.

%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  ReadXBMImage() reads an X11 bitmap image file and returns it.  It
%  allocates the memory necessary for the new Image structure and returns a
%  pointer to the new image.
%
%  The format of the ReadXBMImage method is:
%
%      Image *ReadXBMImage(const ImageInfo *image_info,ExceptionInfo *exception)
%
%  A description of each parameter follows:
%
%    o image_info: the image info.
%
%    o exception: return any errors or warnings in this structure.
%
*/

static unsigned int XBMInteger(Image *image,short int *hex_digits)
{ 
  int
    c;
  
  unsigned int
    value;
  
  /*
    Skip any leading whitespace.
  */
  do
  { 
    c=ReadBlobByte(image);
    if (c == EOF)
      return(0);
  } while ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r'));
  /*
    Evaluate number.
  */
  value=0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -135,7 +135,7 @@
 %
 */
 
-static unsigned int XBMInteger(Image *image,short int *hex_digits)
+static int XBMInteger(Image *image,short int *hex_digits)
 { 
   int
     c;
@@ -150,7 +150,7 @@
   { 
     c=ReadBlobByte(image);
     if (c == EOF)
-      return(0);
+      return(-1);
   } while ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r'));
   /*
     Evaluate number.
@@ -166,9 +166,9 @@
     value+=hex_digits[c];
     c=ReadBlobByte(image);
     if (c == EOF)
-      return(0);
+      return(-1);
   }
-  return(value);
+  return((int) value);
 }
 
 static Image *ReadXBMImage(const ImageInfo *image_info,ExceptionInfo *exception)
@@ -179,6 +179,9 @@
 
   Image
     *image;
+
+  int
+    c;
 
   MagickBooleanType
     status;
@@ -212,7 +215,6 @@
     height,
     length,
     padding,
-    value,
     version,
     width;
 
@@ -353,16 +355,25 @@
   if (version == 10)
     for (i=0; i < (ssize_t) (bytes_per_line*image->rows); (i+=2))
     {
-      value=XBMInteger(image,hex_digits);
-      *p++=(unsigned char) value;
+      c=XBMInteger(image,hex_digits);
+      if (c < 0)
+        break;
+      *p++=(unsigned char) c;
       if ((padding == 0) || (((i+2) % bytes_per_line) != 0))
-        *p++=(unsigned char) (value >> 8);
+        *p++=(unsigned char) (c >> 8);
     }
   else
     for (i=0; i < (ssize_t) (bytes_per_line*image->rows); i++)
     {
       value=XBMInteger(image,hex_digits);
-      *p++=(unsigned char) value;
+      if (c < 0)
+        break;
+      *p++=(unsigned char) c;
+    }
+  if (EOFBlob(image) != MagickFalse)
+    {
+      data=(unsigned char *) RelinquishMagickMemory(data);
+      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
     }
   /*
     Convert X bitmap image to pixel packets.
@@ -379,7 +390,7 @@
     for (x=0; x < (ssize_t) image->columns; x++)
     {
       if (bit == 0)
-        byte=(size_t) (*p++);
+        byte=(unsigned int) (*p++);
       SetPixelIndex(indexes+x,(byte & 0x01) != 0 ? 0x01 : 0x00);
       bit++;
       byte>>=1;
```
