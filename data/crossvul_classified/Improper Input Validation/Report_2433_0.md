# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2433_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2433_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2354-2394 of the vulnerable file.


/*
  Skip the mipmap images for compressed (DXTn) dds files
*/
static MagickBooleanType SkipDXTMipmaps(Image *image,DDSInfo *dds_info,
  int texel_size,ExceptionInfo *exception)
{
  register ssize_t
    i;

  MagickOffsetType
    offset;

  size_t
    h,
    w;

  /*
    Only skip mipmaps for textures and cube maps
  */
  if (dds_info->ddscaps1 & DDSCAPS_MIPMAP
      && (dds_info->ddscaps1 & DDSCAPS_TEXTURE
          || dds_info->ddscaps2 & DDSCAPS2_CUBEMAP))
    {
      if (EOFBlob(image) != MagickFalse)
        {
          ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
            image->filename);
          return(MagickFalse);
        }
      w = DIV2(dds_info->width);
      h = DIV2(dds_info->height);

      /*
        Mipmapcount includes the main image, so start from one
      */
      for (i = 1; (i < (ssize_t) dds_info->mipmapcount) && w && h; i++)
      {
        offset = (MagickOffsetType) ((w + 3) / 4) * ((h + 3) / 4) * texel_size;
        (void) SeekBlob(image, offset, SEEK_CUR);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2371,16 +2371,16 @@
   /*
     Only skip mipmaps for textures and cube maps
   */
+  if (EOFBlob(image) != MagickFalse)
+    {
+      ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
+        image->filename);
+      return(MagickFalse);
+    }
   if (dds_info->ddscaps1 & DDSCAPS_MIPMAP
       && (dds_info->ddscaps1 & DDSCAPS_TEXTURE
           || dds_info->ddscaps2 & DDSCAPS2_CUBEMAP))
     {
-      if (EOFBlob(image) != MagickFalse)
-        {
-          ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
-            image->filename);
-          return(MagickFalse);
-        }
       w = DIV2(dds_info->width);
       h = DIV2(dds_info->height);
 
@@ -2418,16 +2418,16 @@
   /*
     Only skip mipmaps for textures and cube maps
   */
+  if (EOFBlob(image) != MagickFalse)
+    {
+      ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
+        image->filename);
+      return(MagickFalse);
+    }
   if (dds_info->ddscaps1 & DDSCAPS_MIPMAP
       && (dds_info->ddscaps1 & DDSCAPS_TEXTURE
           || dds_info->ddscaps2 & DDSCAPS2_CUBEMAP))
     {
-      if (EOFBlob(image) != MagickFalse)
-        {
-          ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
-            image->filename);
-          return(MagickFalse);
-        }
       w = DIV2(dds_info->width);
       h = DIV2(dds_info->height);
 
```
