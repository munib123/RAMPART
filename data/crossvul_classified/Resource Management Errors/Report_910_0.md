# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 910_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `910_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 737-777 of the vulnerable file.

      page.height=(size_t) ceil((double) ((hires_bounds.y2-hires_bounds.y1)*
        resolution.y/delta.y)-0.5);
    }
  fitPage=MagickFalse;
  option=GetImageOption(image_info,"eps:fit-page");
  if (option != (char *) NULL)
    {
      char
        *geometry;

      MagickStatusType
        flags;

      geometry=GetPageGeometry(option);
      flags=ParseMetaGeometry(geometry,&page.x,&page.y,&page.width,
        &page.height);
      if (flags == NoValue)
        {
          (void) ThrowMagickException(exception,GetMagickModule(),OptionError,
            "InvalidGeometry","`%s'",option);
          image=DestroyImage(image);
          return((Image *) NULL);
        }
      page.width=(size_t) ceil((double) (page.width*image->x_resolution/delta.x)
        -0.5);
      page.height=(size_t) ceil((double) (page.height*image->y_resolution/
        delta.y) -0.5);
      geometry=DestroyString(geometry);
      fitPage=MagickTrue;
    }
  if (IssRGBCompatibleColorspace(image_info->colorspace) != MagickFalse)
    cmyk=MagickFalse;
  /*
    Create Ghostscript control file.
  */
  file=AcquireUniqueFileResource(postscript_filename);
  if (file == -1)
    {
      ThrowFileException(&image->exception,FileOpenError,"UnableToOpenFile",
        image_info->filename);
      image=DestroyImageList(image);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -754,6 +754,7 @@
         {
           (void) ThrowMagickException(exception,GetMagickModule(),OptionError,
             "InvalidGeometry","`%s'",option);
+          geometry=DestroyString(geometry);
           image=DestroyImage(image);
           return((Image *) NULL);
         }
```
