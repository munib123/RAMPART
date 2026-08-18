# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 927_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `927_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1966-2006 of the vulnerable file.

      r=p+GetPixelChannels(image)*(image->columns+4);
      EnhancePixel(8.0); EnhancePixel(20.0); EnhancePixel(40.0);
        EnhancePixel(20.0); EnhancePixel(8.0);
      r=p+2*GetPixelChannels(image)*(image->columns+4);
      EnhancePixel(10.0); EnhancePixel(40.0); EnhancePixel(80.0);
        EnhancePixel(40.0); EnhancePixel(10.0);
      r=p+3*GetPixelChannels(image)*(image->columns+4);
      EnhancePixel(8.0); EnhancePixel(20.0); EnhancePixel(40.0);
        EnhancePixel(20.0); EnhancePixel(8.0);
      r=p+4*GetPixelChannels(image)*(image->columns+4);
      EnhancePixel(5.0); EnhancePixel(8.0); EnhancePixel(10.0);
        EnhancePixel(8.0); EnhancePixel(5.0);
      if (total_weight > MagickEpsilon)
        {
          pixel.red=((aggregate.red+total_weight/2.0)/total_weight);
          pixel.green=((aggregate.green+total_weight/2.0)/total_weight);
          pixel.blue=((aggregate.blue+total_weight/2.0)/total_weight);
          pixel.black=((aggregate.black+total_weight/2.0)/total_weight);
          pixel.alpha=((aggregate.alpha+total_weight/2.0)/total_weight);
        }
      SetPixelViaPixelInfo(image,&pixel,q);
      p+=GetPixelChannels(image);
      q+=GetPixelChannels(enhance_image);
    }
    if (SyncCacheViewAuthenticPixels(enhance_view,exception) == MagickFalse)
      status=MagickFalse;
    if (image->progress_monitor != (MagickProgressMonitor) NULL)
      {
        MagickBooleanType
          proceed;

#if defined(MAGICKCORE_OPENMP_SUPPORT)
        #pragma omp atomic
#endif
        progress++;
        proceed=SetImageProgress(image,EnhanceImageTag,progress,image->rows);
        if (proceed == MagickFalse)
          status=MagickFalse;
      }
  }
  enhance_view=DestroyCacheView(enhance_view);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1983,7 +1983,7 @@
           pixel.black=((aggregate.black+total_weight/2.0)/total_weight);
           pixel.alpha=((aggregate.alpha+total_weight/2.0)/total_weight);
         }
-      SetPixelViaPixelInfo(image,&pixel,q);
+      SetPixelViaPixelInfo(enhance_image,&pixel,q);
       p+=GetPixelChannels(image);
       q+=GetPixelChannels(enhance_image);
     }
```
