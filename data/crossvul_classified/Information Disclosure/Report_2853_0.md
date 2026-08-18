# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2853_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2853_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1010-1050 of the vulnerable file.

      return((Image *) NULL);
    }
  /*
    Determine if this a GIF file.
  */
  count=ReadBlob(image,6,buffer);
  if ((count != 6) || ((LocaleNCompare((char *) buffer,"GIF87",5) != 0) &&
      (LocaleNCompare((char *) buffer,"GIF89",5) != 0)))
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  page.width=ReadBlobLSBShort(image);
  page.height=ReadBlobLSBShort(image);
  flag=(unsigned char) ReadBlobByte(image);
  background=(unsigned char) ReadBlobByte(image);
  c=(unsigned char) ReadBlobByte(image);  /* reserved */
  one=1;
  global_colors=one << (((size_t) flag & 0x07)+1);
  global_colormap=(unsigned char *) AcquireQuantumMemory((size_t)
    MagickMax(global_colors,256),3UL*sizeof(*global_colormap));
  if (global_colormap == (unsigned char *) NULL)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
  if (BitSet((int) flag,0x80) != 0)
    {
      count=ReadBlob(image,(size_t) (3*global_colors),global_colormap);
      if (count != (ssize_t) (3*global_colors))
        {
          global_colormap=(unsigned char *) RelinquishMagickMemory(
            global_colormap);
          ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
        }
    }
  delay=0;
  dispose=0;
  duration=0;
  iterations=1;
  opacity=(-1);
  image_count=0;
  meta_image=AcquireImage(image_info,exception);  /* metadata container */
  for ( ; ; )
  {
    count=ReadBlob(image,1,&c);
    if (count != 1)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1027,6 +1027,8 @@
     MagickMax(global_colors,256),3UL*sizeof(*global_colormap));
   if (global_colormap == (unsigned char *) NULL)
     ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+  (void) ResetMagickMemory(global_colormap,0,3*MagickMax(global_colors,256)*
+    sizeof(*global_colormap));
   if (BitSet((int) flag,0x80) != 0)
     {
       count=ReadBlob(image,(size_t) (3*global_colors),global_colormap);
```
