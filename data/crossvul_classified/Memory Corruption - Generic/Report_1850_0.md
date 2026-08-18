# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1850_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1850_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 314-354 of the vulnerable file.

      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    if ((sun_info.type != RT_STANDARD) && (sun_info.type != RT_ENCODED) &&
        (sun_info.type != RT_FORMAT_RGB))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    if ((sun_info.maptype == RMT_NONE) && (sun_info.maplength != 0))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    if ((sun_info.depth == 0) || (sun_info.depth > 32))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    if ((sun_info.maptype != RMT_NONE) && (sun_info.maptype != RMT_EQUAL_RGB) &&
        (sun_info.maptype != RMT_RAW))
      ThrowReaderException(CoderError,"ColormapTypeNotSupported");
    image->columns=sun_info.width;
    image->rows=sun_info.height;
    image->depth=sun_info.depth <= 8 ? sun_info.depth :
      MAGICKCORE_QUANTUM_DEPTH;
    if (sun_info.depth < 24)
      {
        size_t
          one;

        image->storage_class=PseudoClass;
        image->colors=sun_info.maplength;
        one=1;
        if (sun_info.maptype == RMT_NONE)
          image->colors=one << sun_info.depth;
        if (sun_info.maptype == RMT_EQUAL_RGB)
          image->colors=sun_info.maplength/3;
      }
    switch (sun_info.maptype)
    {
      case RMT_NONE:
      {
        if (sun_info.depth < 24)
          {
            /*
              Create linear color ramp.
            */
            if (AcquireImageColormap(image,image->colors,exception) == MagickFalse)
              ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
          }
        break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -331,28 +331,17 @@
         size_t
           one;
 
-        image->storage_class=PseudoClass;
         image->colors=sun_info.maplength;
         one=1;
         if (sun_info.maptype == RMT_NONE)
           image->colors=one << sun_info.depth;
         if (sun_info.maptype == RMT_EQUAL_RGB)
           image->colors=sun_info.maplength/3;
+        if (AcquireImageColormap(image,image->colors,exception) == MagickFalse)
+          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
       }
     switch (sun_info.maptype)
     {
-      case RMT_NONE:
-      {
-        if (sun_info.depth < 24)
-          {
-            /*
-              Create linear color ramp.
-            */
-            if (AcquireImageColormap(image,image->colors,exception) == MagickFalse)
-              ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-          }
-        break;
-      }
       case RMT_EQUAL_RGB:
       {
         unsigned char
@@ -361,8 +350,6 @@
         /*
           Read SUN raster colormap.
         */
-        if (AcquireImageColormap(image,image->colors,exception) == MagickFalse)
-          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
         sun_colormap=(unsigned char *) AcquireQuantumMemory(image->colors,
           sizeof(*sun_colormap));
         if (sun_colormap == (unsigned char *) NULL)
```
