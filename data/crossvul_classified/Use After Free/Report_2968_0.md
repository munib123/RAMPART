# CrossVul Fix Pair: Use After Free in cpp
**Pair ID:** 2968_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2968_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```cpp
Lines 5070-5110 of the vulnerable file.

  if (image != (MagickCore::Image *) NULL &&
      image->next != (MagickCore::Image *) NULL)
    {
      MagickCore::Image
        *next;

      // Destroy any extra image frames
      next=image->next;
      image->next=(MagickCore::Image *) NULL;
      next->previous=(MagickCore::Image *) NULL;
      DestroyImageList(next);
    }
  replaceImage(image);
  if (exceptionInfo->severity == MagickCore::UndefinedException &&
      image == (MagickCore::Image *) NULL)
    {
      (void) MagickCore::DestroyExceptionInfo(exceptionInfo);
      if (!quiet())
        throwExceptionExplicit(MagickCore::ImageWarning,
          "No image was loaded.");
    }
  ThrowImageException;
}

void Magick::Image::floodFill(const ssize_t x_,const ssize_t y_,
  const Magick::Image *fillPattern_,const Magick::Color &fill_,
  const MagickCore::PixelInfo *target_,const bool invert_)
{
  Magick::Color
    fillColor;

  MagickCore::Image
    *fillPattern;

  // Set drawing fill pattern or fill color
  fillColor=options()->fillColor();
  fillPattern=(MagickCore::Image *)NULL;
  if (options()->fillPattern() != (MagickCore::Image *)NULL)
    {
      GetPPException;
      fillPattern=CloneImage(options()->fillPattern(),0,0,MagickTrue,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5087,6 +5087,7 @@
       if (!quiet())
         throwExceptionExplicit(MagickCore::ImageWarning,
           "No image was loaded.");
+      return;
     }
   ThrowImageException;
 }
```
