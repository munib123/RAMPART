# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3195_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3195_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 699-739 of the vulnerable file.

                ((green & 0x18) >> 3));
              (void) WriteBlobByte(image,value);
          }
        else
          {
            (void) WriteBlobByte(image,ScaleQuantumToChar(GetPixelBlue(p)));
            (void) WriteBlobByte(image,ScaleQuantumToChar(GetPixelGreen(p)));
            (void) WriteBlobByte(image,ScaleQuantumToChar(GetPixelRed(p)));
            if (image->matte != MagickFalse)
              (void) WriteBlobByte(image,ScaleQuantumToChar(GetPixelAlpha(p)));
          }
    }
}

static MagickBooleanType WriteTGAImage(const ImageInfo *image_info,Image *image)
{
  CompressionType
    compression;

  const char
    *value;

  const double
    midpoint = QuantumRange/2.0;

  MagickBooleanType
    status;

  QuantumAny
    range;

  register const IndexPacket
    *indexes;

  register const PixelPacket
    *p;

  register ssize_t
    x;

  register ssize_t
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -716,6 +716,7 @@
     compression;
 
   const char
+    *comment,
     *value;
 
   const double
@@ -772,9 +773,9 @@
     compression=image_info->compression;
   range=GetQuantumRange(5UL);
   tga_info.id_length=0;
-  value=GetImageProperty(image,"comment");
-  if (value != (const char *) NULL)
-    tga_info.id_length=(unsigned char) MagickMin(strlen(value),255);
+  comment=GetImageProperty(image,"comment");
+  if (comment != (const char *) NULL)
+    tga_info.id_length=(unsigned char) MagickMin(strlen(comment),255);
   tga_info.colormap_type=0;
   tga_info.colormap_index=0;
   tga_info.colormap_length=0;
@@ -858,7 +859,7 @@
   (void) WriteBlobByte(image,tga_info.bits_per_pixel);
   (void) WriteBlobByte(image,tga_info.attributes);
   if (tga_info.id_length != 0)
-    (void) WriteBlob(image,tga_info.id_length,(unsigned char *) value);
+    (void) WriteBlob(image,tga_info.id_length,(unsigned char *) comment);
   if (tga_info.colormap_type != 0)
     {
       unsigned char
```
