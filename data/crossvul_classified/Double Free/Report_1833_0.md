# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1833_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1833_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 301-341 of the vulnerable file.

      count=ReadBlob(image,tga_info.id_length,(unsigned char *) comment);
      comment[tga_info.id_length]='\0';
      (void) SetImageProperty(image,"comment",comment,exception);
      comment=DestroyString(comment);
    }
  if (image_info->ping != MagickFalse)
    {
      (void) CloseBlob(image);
      return(image);
    }
  status=SetImageExtent(image,image->columns,image->rows,exception);
  if (status == MagickFalse)
    return(DestroyImageList(image));
  (void) ResetMagickMemory(&pixel,0,sizeof(pixel));
  pixel.alpha=(MagickRealType) OpaqueAlpha;
  if (tga_info.colormap_type != 0)
    {
      /*
        Read TGA raster colormap.
      */
      if (AcquireImageColormap(image,image->colors,exception) == MagickFalse)
        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
      for (i=0; i < (ssize_t) tga_info.colormap_index; i++)
        image->colormap[i]=pixel;
      for ( ; i < (ssize_t) image->colors; i++)
      {
        switch (tga_info.colormap_size)
        {
          case 8:
          default:
          {
            /*
              Gray scale.
            */
            pixel.red=(MagickRealType) ScaleCharToQuantum((unsigned char)
              ReadBlobByte(image));
            pixel.green=pixel.red;
            pixel.blue=pixel.red;
            break;
          }
          case 15:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -318,6 +318,8 @@
       /*
         Read TGA raster colormap.
       */
+      if (image->colors < tga_info.colormap_index)
+        image->colors=tga_info.colormap_index;
       if (AcquireImageColormap(image,image->colors,exception) == MagickFalse)
         ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
       for (i=0; i < (ssize_t) tga_info.colormap_index; i++)
```
