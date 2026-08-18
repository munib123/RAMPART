# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4815_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4815_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 222-262 of the vulnerable file.

  if (status == MagickFalse)
    {
      draw_info=DestroyDrawInfo(draw_info);
      InheritException(exception,&image->exception);
      return(DestroyImageList(image));
    }
  if (SetImageBackgroundColor(image) == MagickFalse)
    {
      draw_info=DestroyDrawInfo(draw_info);
      InheritException(exception,&image->exception);
      image=DestroyImageList(image);
      return((Image *) NULL);
    }
  /*
    Draw label.
  */
  (void) FormatLocaleString(geometry,MaxTextExtent,"%+g%+g",
    draw_info->direction == RightToLeftDirection ? image->columns-
    metrics.bounds.x2 : 0.0,draw_info->gravity == UndefinedGravity ?
    metrics.ascent : 0.0);
  draw_info->geometry=AcquireString(geometry);
  status=AnnotateImage(image,draw_info);
  if (image_info->pointsize == 0.0)
    {
      char
        pointsize[MaxTextExtent];

      (void) FormatLocaleString(pointsize,MaxTextExtent,"%.20g",
        draw_info->pointsize);
      (void) SetImageProperty(image,"label:pointsize",pointsize);
    }
  draw_info=DestroyDrawInfo(draw_info);
  if (status == MagickFalse)
    {
      image=DestroyImageList(image);
      return((Image *) NULL);
    }
  return(GetFirstImageInList(image));
}


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -239,7 +239,7 @@
     draw_info->direction == RightToLeftDirection ? image->columns-
     metrics.bounds.x2 : 0.0,draw_info->gravity == UndefinedGravity ?
     metrics.ascent : 0.0);
-  draw_info->geometry=AcquireString(geometry);
+  (void) CloneString(&draw_info->geometry,geometry);
   status=AnnotateImage(image,draw_info);
   if (image_info->pointsize == 0.0)
     {
```
