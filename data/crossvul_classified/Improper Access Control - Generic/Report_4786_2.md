# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 4786_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4786_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 124-164 of the vulnerable file.

%  ReadVIFFImage() reads a Khoros Visualization image file and returns
%  it.  It allocates the memory necessary for the new Image structure and
%  returns a pointer to the new image.
%
%  The format of the ReadVIFFImage method is:
%
%      Image *ReadVIFFImage(const ImageInfo *image_info,
%        ExceptionInfo *exception)
%
%  A description of each parameter follows:
%
%    o image: Method ReadVIFFImage returns a pointer to the image after
%      reading.  A null image is returned if there is a memory shortage or if
%      the image cannot be read.
%
%    o image_info: the image info.
%
%    o exception: return any errors or warnings in this structure.
%
*/
static Image *ReadVIFFImage(const ImageInfo *image_info,
  ExceptionInfo *exception)
{
#define VFF_CM_genericRGB  15
#define VFF_CM_ntscRGB  1
#define VFF_CM_NONE  0
#define VFF_DEP_DECORDER  0x4
#define VFF_DEP_NSORDER  0x8
#define VFF_DES_RAW  0
#define VFF_LOC_IMPLICIT  1
#define VFF_MAPTYP_NONE  0
#define VFF_MAPTYP_1_BYTE  1
#define VFF_MAPTYP_2_BYTE  2
#define VFF_MAPTYP_4_BYTE  4
#define VFF_MAPTYP_FLOAT  5
#define VFF_MAPTYP_DOUBLE  7
#define VFF_MS_NONE  0
#define VFF_MS_ONEPERBAND  1
#define VFF_MS_SHARED  3
#define VFF_TYP_BIT  0
#define VFF_TYP_1_BYTE  1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,6 +141,22 @@
 %    o exception: return any errors or warnings in this structure.
 %
 */
+
+static MagickBooleanType CheckMemoryOverflow(const size_t count,
+  const size_t quantum)
+{
+  size_t
+    size;
+
+  size=count*quantum;
+  if ((count == 0) || (quantum != (size/count)))
+    {
+      errno=ENOMEM;
+      return(MagickTrue);
+    }
+  return(MagickFalse);
+}
+
 static Image *ReadVIFFImage(const ImageInfo *image_info,
   ExceptionInfo *exception)
 {
@@ -479,7 +495,7 @@
     /*
       Initialize image structure.
     */
-    image->alpha_trait=viff_info.number_data_bands == 4 ? BlendPixelTrait : 
+    image->alpha_trait=viff_info.number_data_bands == 4 ? BlendPixelTrait :
       UndefinedPixelTrait;
     image->storage_class=(viff_info.number_data_bands < 3 ? PseudoClass :
       DirectClass);
@@ -503,9 +519,17 @@
       default: bytes_per_pixel=1; break;
     }
     if (viff_info.data_storage_type == VFF_TYP_BIT)
-      max_packets=((image->columns+7UL) >> 3UL)*image->rows;
+      {
+        if (CheckMemoryOverflow((image->columns+7UL) >> 3UL,image->rows) != MagickFalse)
+          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+        max_packets=((image->columns+7UL) >> 3UL)*image->rows;
+      }
     else
-      max_packets=(size_t) (number_pixels*viff_info.number_data_bands);
+      {
+        if (CheckMemoryOverflow(number_pixels,viff_info.number_data_bands) != MagickFalse)
+          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+        max_packets=(size_t) (number_pixels*viff_info.number_data_bands);
+      }
     pixels=(unsigned char *) AcquireQuantumMemory(MagickMax(number_pixels,
       max_packets),bytes_per_pixel*sizeof(*pixels));
     if (pixels == (unsigned char *) NULL)
@@ -699,7 +723,7 @@
                 {
                   ssize_t
                     index;
-                  
+
                   index=(ssize_t) GetPixelRed(image,q);
                   SetPixelRed(image,image->colormap[
                     ConstrainColormapIndex(image,index,exception)].red,q);
```
