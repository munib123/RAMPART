# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2434_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2434_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1820-1860 of the vulnerable file.

    {
      /*
        Determine number of faces defined in the cubemap
      */
      num_images = 0;
      if (dds_info.ddscaps2 & DDSCAPS2_CUBEMAP_POSITIVEX) num_images++;
      if (dds_info.ddscaps2 & DDSCAPS2_CUBEMAP_NEGATIVEX) num_images++;
      if (dds_info.ddscaps2 & DDSCAPS2_CUBEMAP_POSITIVEY) num_images++;
      if (dds_info.ddscaps2 & DDSCAPS2_CUBEMAP_NEGATIVEY) num_images++;
      if (dds_info.ddscaps2 & DDSCAPS2_CUBEMAP_POSITIVEZ) num_images++;
      if (dds_info.ddscaps2 & DDSCAPS2_CUBEMAP_NEGATIVEZ) num_images++;
    }

  if (volume)
    num_images = dds_info.depth;

  for (n = 0; n < num_images; n++)
  {
    if (n != 0)
      {
        /* Start a new image */
        AcquireNextImage(image_info,image);
        if (GetNextImageInList(image) == (Image *) NULL)
          return(DestroyImageList(image));
        image=SyncNextImageInList(image);
      }
 
    image->matte = matte;
    image->compression = compression;
    image->columns = dds_info.width;
    image->rows = dds_info.height;
    image->storage_class = DirectClass;
    image->endian = LSBEndian;
    image->depth = 8;
    if (image_info->ping != MagickFalse)
      {
        (void) CloseBlob(image);
        return(GetFirstImageInList(image));
      }
    status=SetImageExtent(image,image->columns,image->rows);
    if (status == MagickFalse)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1837,6 +1837,8 @@
   {
     if (n != 0)
       {
+        if (EOFBlob(image) != MagickFalse)
+          ThrowReaderException(CorruptImageError,"UnexpectedEndOfFile");
         /* Start a new image */
         AcquireNextImage(image_info,image);
         if (GetNextImageInList(image) == (Image *) NULL)
```
