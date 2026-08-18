# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4788_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4788_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 124-179 of the vulnerable file.

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

static MagickBooleanType CheckMemoryOverflow(const size_t count,
  const size_t quantum)
{
  size_t
    size;

  size=count*quantum;
  if ((count == 0) || (quantum != (size/count)))
    {
      errno=ENOMEM;
      return(MagickTrue);
    }
  return(MagickFalse);
}

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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,22 +141,6 @@
 %    o exception: return any errors or warnings in this structure.
 %
 */
-
-static MagickBooleanType CheckMemoryOverflow(const size_t count,
-  const size_t quantum)
-{
-  size_t
-    size;
-
-  size=count*quantum;
-  if ((count == 0) || (quantum != (size/count)))
-    {
-      errno=ENOMEM;
-      return(MagickTrue);
-    }
-  return(MagickFalse);
-}
-
 static Image *ReadVIFFImage(const ImageInfo *image_info,
   ExceptionInfo *exception)
 {
@@ -524,13 +508,13 @@
     }
     if (viff_info.data_storage_type == VFF_TYP_BIT)
       {
-        if (CheckMemoryOverflow((image->columns+7UL) >> 3UL,image->rows) != MagickFalse)
+        if (HeapOverflowSanityCheck((image->columns+7UL) >> 3UL,image->rows) != MagickFalse)
           ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
         max_packets=((image->columns+7UL) >> 3UL)*image->rows;
       }
     else
       {
-        if (CheckMemoryOverflow(number_pixels,viff_info.number_data_bands) != MagickFalse)
+        if (HeapOverflowSanityCheck(number_pixels,viff_info.number_data_bands) != MagickFalse)
           ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
         max_packets=(size_t) (number_pixels*viff_info.number_data_bands);
       }
```
