# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5332_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5332_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1292-1332 of the vulnerable file.

  status=MagickTrue;
  image_info=AcquireImageInfo();
  image_info->dither=image->dither;
  artifact=GetImageArtifact(image,"dither");
  if (artifact != (const char *) NULL)
    (void) SetImageOption(image_info,"dither",artifact);
  switch (type)
  {
    case BilevelType:
    {
      if (SetImageMonochrome(image,&image->exception) == MagickFalse)
        {
          status=TransformImageColorspace(image,GRAYColorspace);
          (void) NormalizeImage(image);
          quantize_info=AcquireQuantizeInfo(image_info);
          quantize_info->number_colors=2;
          quantize_info->colorspace=GRAYColorspace;
          status=QuantizeImage(quantize_info,image);
          quantize_info=DestroyQuantizeInfo(quantize_info);
        }
      image->colors=2;
      image->matte=MagickFalse;
      break;
    }
    case GrayscaleType:
    {
      if (SetImageGray(image,&image->exception) == MagickFalse)
        status=TransformImageColorspace(image,GRAYColorspace);
      image->matte=MagickFalse;
      break;
    }
    case GrayscaleMatteType:
    {
      if (SetImageGray(image,&image->exception) == MagickFalse)
        status=TransformImageColorspace(image,GRAYColorspace);
      if (image->matte == MagickFalse)
        (void) SetImageAlphaChannel(image,OpaqueAlphaChannel);
      break;
    }
    case PaletteType:
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1309,7 +1309,7 @@
           status=QuantizeImage(quantize_info,image);
           quantize_info=DestroyQuantizeInfo(quantize_info);
         }
-      image->colors=2;
+      status=AcquireImageColormap(image,2);
       image->matte=MagickFalse;
       break;
     }
```
