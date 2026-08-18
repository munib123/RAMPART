# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4815_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4815_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 260-300 of the vulnerable file.

              high=draw_info->pointsize-0.5;
          }
        else
          if (((image->columns != 0) && (width < image->columns)) ||
              ((image->rows != 0) && (height < image->rows)))
            low=draw_info->pointsize+0.5;
          else
            high=draw_info->pointsize-0.5;
      }
      draw_info->pointsize=floor((low+high)/2.0-0.5);
    }
  /*
    Draw caption.
  */
  i=FormatMagickCaption(image,draw_info,split,&metrics,&caption);
  (void) CloneString(&draw_info->text,caption);
  (void) FormatLocaleString(geometry,MaxTextExtent,"%+g%+g",MagickMax(
    draw_info->direction == RightToLeftDirection ? image->columns-
    metrics.bounds.x2 : -metrics.bounds.x1,0.0),draw_info->gravity ==
    UndefinedGravity ? metrics.ascent : 0.0);
  draw_info->geometry=AcquireString(geometry);
  status=AnnotateImage(image,draw_info);
  if (image_info->pointsize == 0.0)
    { 
      char
        pointsize[MaxTextExtent];
      
      (void) FormatLocaleString(pointsize,MaxTextExtent,"%.20g",
        draw_info->pointsize);
      (void) SetImageProperty(image,"caption:pointsize",pointsize);
    }
  draw_info=DestroyDrawInfo(draw_info);
  caption=DestroyString(caption);
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
@@ -277,7 +277,7 @@
     draw_info->direction == RightToLeftDirection ? image->columns-
     metrics.bounds.x2 : -metrics.bounds.x1,0.0),draw_info->gravity ==
     UndefinedGravity ? metrics.ascent : 0.0);
-  draw_info->geometry=AcquireString(geometry);
+  (void) CloneString(&draw_info->geometry,geometry);
   status=AnnotateImage(image,draw_info);
   if (image_info->pointsize == 0.0)
     { 
```
