# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2617_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2617_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 385-425 of the vulnerable file.

  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  status=OpenBlob(image_info,image,WriteBinaryBlobMode,&image->exception);
  if (status == MagickFalse)
    return(status);
  (void) TransformImageColorspace(image,sRGBColorspace);
  /*
    Allocate colormap.
  */
  if (IsPaletteImage(image,&image->exception) == MagickFalse)
    (void) SetImageType(image,PaletteType);
  depth=GetImageQuantumDepth(image,MagickTrue);
  packet_size=(size_t) (depth/8);
  pixels=(unsigned char *) AcquireQuantumMemory(image->columns,packet_size*
    sizeof(*pixels));
  packet_size=(size_t) (image->colors > 256 ? 6UL : 3UL);
  colormap=(unsigned char *) AcquireQuantumMemory(image->colors,packet_size*
    sizeof(*colormap));
  if ((pixels == (unsigned char *) NULL) ||
      (colormap == (unsigned char *) NULL))
    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
  /*
    Write colormap to file.
  */
  q=colormap;
  q=colormap;
  if (image->colors <= 256)
    for (i=0; i < (ssize_t) image->colors; i++)
    {
      *q++=(unsigned char) ScaleQuantumToChar(image->colormap[i].red);
      *q++=(unsigned char) ScaleQuantumToChar(image->colormap[i].green);
      *q++=(unsigned char) ScaleQuantumToChar(image->colormap[i].blue);
    }
  else
    for (i=0; i < (ssize_t) image->colors; i++)
    {
      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].red) >> 8);
      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].red) & 0xff);
      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].green) >> 8);
      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].green) & 0xff);;
      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].blue) >> 8);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -402,11 +402,16 @@
     sizeof(*colormap));
   if ((pixels == (unsigned char *) NULL) ||
       (colormap == (unsigned char *) NULL))
-    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+    {
+      if (colormap != (unsigned char *) NULL)
+        colormap=(unsigned char *) RelinquishMagickMemory(colormap);
+      if (pixels != (unsigned char *) NULL)
+        pixels=(unsigned char *) RelinquishMagickMemory(pixels);
+      ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+    }
   /*
     Write colormap to file.
   */
-  q=colormap;
   q=colormap;
   if (image->colors <= 256)
     for (i=0; i < (ssize_t) image->colors; i++)
@@ -421,9 +426,11 @@
       *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].red) >> 8);
       *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].red) & 0xff);
       *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].green) >> 8);
-      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].green) & 0xff);;
+      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].green) &
+        0xff);
       *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].blue) >> 8);
-      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].blue) & 0xff);
+      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].blue) &
+        0xff);
     }
   (void) WriteBlob(image,packet_size*image->colors,colormap);
   colormap=(unsigned char *) RelinquishMagickMemory(colormap);
```
