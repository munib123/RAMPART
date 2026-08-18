# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 4413_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4413_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 1344-1384 of the vulnerable file.

#endif
    i++;
  }
  prev_image=DestroyImage(prev_image);
  /*
    Optimize all images in sequence.
  */
  sans_exception=AcquireExceptionInfo();
  i=0;
  curr=GetFirstImageInList(image);
  optimized_image=NewImageList();
  while ( curr != (const Image *) NULL )
  {
    prev_image=CloneImage(curr,0,0,MagickTrue,exception);
    if (prev_image == (Image *) NULL)
      break;
    prev_image->background_color.alpha_trait=BlendPixelTrait;
    if ( disposals[i] == DelDispose ) {
      size_t time = 0;
      while ( disposals[i] == DelDispose ) {
        time += curr->delay*1000/curr->ticks_per_second;
        curr=GetNextImageInList(curr);
        i++;
      }
      time += curr->delay*1000/curr->ticks_per_second;
      prev_image->ticks_per_second = 100L;
      prev_image->delay = time*prev_image->ticks_per_second/1000;
    }
    bgnd_image=CropImage(prev_image,&bounds[i],sans_exception);
    prev_image=DestroyImage(prev_image);
    if (bgnd_image == (Image *) NULL)
      break;
    bgnd_image->dispose=disposals[i];
    if ( disposals[i] == DupDispose ) {
      bgnd_image->delay=0;
      bgnd_image->dispose=NoneDispose;
    }
    else
      curr=GetNextImageInList(curr);
    AppendImageToList(&optimized_image,bgnd_image);
    i++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1361,11 +1361,13 @@
     if ( disposals[i] == DelDispose ) {
       size_t time = 0;
       while ( disposals[i] == DelDispose ) {
-        time += curr->delay*1000/curr->ticks_per_second;
+        time +=(size_t) (curr->delay*1000*
+          PerceptibleReciprocal((double) curr->ticks_per_second));
         curr=GetNextImageInList(curr);
         i++;
       }
-      time += curr->delay*1000/curr->ticks_per_second;
+      time += (size_t)(curr->delay*1000*
+        PerceptibleReciprocal((double) curr->ticks_per_second));
       prev_image->ticks_per_second = 100L;
       prev_image->delay = time*prev_image->ticks_per_second/1000;
     }
```
