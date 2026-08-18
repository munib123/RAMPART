# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4781_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4781_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1218-1259 of the vulnerable file.

    }
    case JCS_YCbCr:
    {
      (void) SetImageColorspace(image,YCbCrColorspace);
      break;
    }
    case JCS_CMYK:
    {
      (void) SetImageColorspace(image,CMYKColorspace);
      break;
    }
  }
  if (IsITUFaxImage(image) != MagickFalse)
    {
      (void) SetImageColorspace(image,LabColorspace);
      jpeg_info.out_color_space=JCS_YCbCr;
    }
  if (option != (const char *) NULL)
    if (AcquireImageColormap(image,StringToUnsignedLong(option)) == MagickFalse)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
  if ((jpeg_info.output_components == 1) &&
      (jpeg_info.quantize_colors == 0))
    {
      size_t
        colors;

      colors=(size_t) GetQuantumRange(image->depth)+1;
      if (AcquireImageColormap(image,colors) == MagickFalse)
        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    }
  if (image->debug != MagickFalse)
    {
      if (image->interlace != NoInterlace)
        (void) LogMagickEvent(CoderEvent,GetMagickModule(),
          "Interlace: progressive");
      else
        (void) LogMagickEvent(CoderEvent,GetMagickModule(),
          "Interlace: nonprogressive");
      (void) LogMagickEvent(CoderEvent,GetMagickModule(),"Data precision: %d",
        (int) jpeg_info.data_precision);
      (void) LogMagickEvent(CoderEvent,GetMagickModule(),"Geometry: %dx%d",
        (int) jpeg_info.output_width,(int) jpeg_info.output_height);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1235,8 +1235,7 @@
   if (option != (const char *) NULL)
     if (AcquireImageColormap(image,StringToUnsignedLong(option)) == MagickFalse)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-  if ((jpeg_info.output_components == 1) &&
-      (jpeg_info.quantize_colors == 0))
+  if ((jpeg_info.output_components == 1) && (jpeg_info.quantize_colors == 0))
     {
       size_t
         colors;
```
