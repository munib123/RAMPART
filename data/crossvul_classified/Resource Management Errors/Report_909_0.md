# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 909_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `909_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 732-772 of the vulnerable file.

      (void) SetImageProperty(image,"ps:HiResBoundingBox",geometry,exception);
      page.width=(size_t) ceil((double) ((hires_bounds.x2-hires_bounds.x1)*
        resolution.x/delta.x)-0.5);
      page.height=(size_t) ceil((double) ((hires_bounds.y2-hires_bounds.y1)*
        resolution.y/delta.y)-0.5);
    }
  fitPage=MagickFalse;
  option=GetImageOption(image_info,"eps:fit-page");
  if (option != (char *) NULL)
    {
      char
        *page_geometry;

      page_geometry=GetPageGeometry(option);
      flags=ParseMetaGeometry(page_geometry,&page.x,&page.y,&page.width,
        &page.height);
      if (flags == NoValue)
        {
          (void) ThrowMagickException(exception,GetMagickModule(),OptionError,
            "InvalidGeometry","`%s'",option);
          image=DestroyImage(image);
          return((Image *) NULL);
        }
      page.width=(size_t) ceil((double) (page.width*image->resolution.x/delta.x)
        -0.5);
      page.height=(size_t) ceil((double) (page.height*image->resolution.y/
        delta.y) -0.5);
      page_geometry=DestroyString(page_geometry);
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
      ThrowFileException(exception,FileOpenError,"UnableToOpenFile",
        image_info->filename);
      image=DestroyImageList(image);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -749,6 +749,7 @@
         {
           (void) ThrowMagickException(exception,GetMagickModule(),OptionError,
             "InvalidGeometry","`%s'",option);
+          page_geometry=DestroyString(page_geometry);
           image=DestroyImage(image);
           return((Image *) NULL);
         }
```
