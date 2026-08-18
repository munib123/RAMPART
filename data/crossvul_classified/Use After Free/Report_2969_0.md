# CrossVul Fix Pair: Use After Free in cpp
**Pair ID:** 2969_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2969_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```cpp
Lines 5123-5163 of the vulnerable file.

  MagickCore::ExceptionInfo *exceptionInfo)
{
  // Ensure that multiple image frames were not read.
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
      throwExceptionExplicit(ImageWarning,"No image was loaded.");
    }
  ThrowImageException;
  if (image != (MagickCore::Image *) NULL)
    throwException(&image->exception,quiet());
}

void Magick::Image::floodFill(const ssize_t x_,const ssize_t y_,
  const Magick::Image *fillPattern_,const Magick::Color &fill_,
  const MagickCore::PixelPacket *target_,const bool invert_)
{
  Magick::Color
    fillColor;

  MagickCore::Image
    *fillPattern;

  MagickPixelPacket
    target;

  // Set drawing fill pattern or fill color
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5140,9 +5140,14 @@
       image == (MagickCore::Image *) NULL)
     {
       (void) MagickCore::DestroyExceptionInfo(exceptionInfo);
-      throwExceptionExplicit(ImageWarning,"No image was loaded.");
+      if (!quiet())
+        throwExceptionExplicit(MagickCore::ImageWarning,
+          "No image was loaded.");
     }
-  ThrowImageException;
+  else
+    {
+      ThrowImageException;
+    }
   if (image != (MagickCore::Image *) NULL)
     throwException(&image->exception,quiet());
 }
```
