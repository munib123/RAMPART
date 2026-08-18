# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4779_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4779_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 390-430 of the vulnerable file.

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
  if (image->depth <= 8)
    for (i=0; i < (ssize_t) image->colors; i++)
    {
      *q++=(unsigned char) image->colormap[i].red;
      *q++=(unsigned char) image->colormap[i].green;
      *q++=(unsigned char) image->colormap[i].blue;
    }
  else
    for (i=0; i < (ssize_t) image->colors; i++)
    {
      *q++=(unsigned char) ((size_t) image->colormap[i].red >> 8);
      *q++=(unsigned char) image->colormap[i].red;
      *q++=(unsigned char) ((size_t) image->colormap[i].green >> 8);
      *q++=(unsigned char) image->colormap[i].green;
      *q++=(unsigned char) ((size_t) image->colormap[i].blue >> 8);
      *q++=(unsigned char) image->colormap[i].blue;
    }
  (void) WriteBlob(image,packet_size*image->colors,colormap);
  colormap=(unsigned char *) RelinquishMagickMemory(colormap);
  /*
    Write image pixels to file.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -407,22 +407,23 @@
     Write colormap to file.
   */
   q=colormap;
-  if (image->depth <= 8)
+  q=colormap;
+  if (image->colors <= 256)
     for (i=0; i < (ssize_t) image->colors; i++)
     {
-      *q++=(unsigned char) image->colormap[i].red;
-      *q++=(unsigned char) image->colormap[i].green;
-      *q++=(unsigned char) image->colormap[i].blue;
+      *q++=(unsigned char) ScaleQuantumToChar(image->colormap[i].red);
+      *q++=(unsigned char) ScaleQuantumToChar(image->colormap[i].green);
+      *q++=(unsigned char) ScaleQuantumToChar(image->colormap[i].blue);
     }
   else
     for (i=0; i < (ssize_t) image->colors; i++)
     {
-      *q++=(unsigned char) ((size_t) image->colormap[i].red >> 8);
-      *q++=(unsigned char) image->colormap[i].red;
-      *q++=(unsigned char) ((size_t) image->colormap[i].green >> 8);
-      *q++=(unsigned char) image->colormap[i].green;
-      *q++=(unsigned char) ((size_t) image->colormap[i].blue >> 8);
-      *q++=(unsigned char) image->colormap[i].blue;
+      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].red) >> 8);
+      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].red) & 0xff);
+      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].green) >> 8);
+      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].green) & 0xff);;
+      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].blue) >> 8);
+      *q++=(unsigned char) (ScaleQuantumToShort(image->colormap[i].blue) & 0xff);
     }
   (void) WriteBlob(image,packet_size*image->colors,colormap);
   colormap=(unsigned char *) RelinquishMagickMemory(colormap);
```
