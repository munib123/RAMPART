# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 946_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `946_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 7815-7855 of the vulnerable file.

            if (channel_image == (Image *) NULL)
              {
                status=MagickFalse;
                break;
              }
            *images=DestroyImageList(*images);
            *images=channel_image;
            break;
          }
        if (LocaleCompare("clut",option+1) == 0)
          {
            Image
              *clut_image,
              *image;

            (void) SyncImagesSettings(mogrify_info,*images,exception);
            image=RemoveFirstImageFromList(images);
            clut_image=RemoveFirstImageFromList(images);
            if (clut_image == (Image *) NULL)
              {
                status=MagickFalse;
                break;
              }
            (void) ClutImage(image,clut_image,interpolate_method,exception);
            clut_image=DestroyImage(clut_image);
            *images=DestroyImageList(*images);
            *images=image;
            break;
          }
        if (LocaleCompare("coalesce",option+1) == 0)
          {
            Image
              *coalesce_image;

            (void) SyncImagesSettings(mogrify_info,*images,exception);
            coalesce_image=CoalesceImages(*images,exception);
            if (coalesce_image == (Image *) NULL)
              {
                status=MagickFalse;
                break;
              }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7832,6 +7832,9 @@
             clut_image=RemoveFirstImageFromList(images);
             if (clut_image == (Image *) NULL)
               {
+                (void) ThrowMagickException(exception,GetMagickModule(),
+                  OptionError,"ImageSequenceRequired","`%s'",option);
+                image=DestroyImage(image);
                 status=MagickFalse;
                 break;
               }
@@ -7904,6 +7907,9 @@
             reconstruct_image=RemoveFirstImageFromList(images);
             if (reconstruct_image == (Image *) NULL)
               {
+                (void) ThrowMagickException(exception,GetMagickModule(),
+                  OptionError,"ImageSequenceRequired","`%s'",option);
+                image=DestroyImage(image);
                 status=MagickFalse;
                 break;
               }
@@ -7984,7 +7990,13 @@
             new_images=RemoveFirstImageFromList(images);
             source_image=RemoveFirstImageFromList(images);
             if (source_image == (Image *) NULL)
-              break; /* FUTURE - produce Exception, rather than silent fail */
+              {
+                (void) ThrowMagickException(exception,GetMagickModule(),
+                  OptionError,"ImageSequenceRequired","`%s'",option);
+                new_images=DestroyImage(new_images);
+                status=MagickFalse;
+                break;
+              }
 
             /* FUTURE: this should not be here! - should be part of -geometry */
             if (source_image->geometry != (char *) NULL)
@@ -8236,6 +8248,9 @@
             hald_image=RemoveFirstImageFromList(images);
             if (hald_image == (Image *) NULL)
               {
+                (void) ThrowMagickException(exception,GetMagickModule(),
+                  OptionError,"ImageSequenceRequired","`%s'",option);
+                image=DestroyImage(image);
                 status=MagickFalse;
                 break;
               }
@@ -8265,11 +8280,16 @@
             phase_image=RemoveFirstImageFromList(images);
             if (phase_image == (Image *) NULL)
               {
+                (void) ThrowMagickException(exception,GetMagickModule(),
+                  OptionError,"ImageSequenceRequired","`%s'",option);
+                magnitude_image=DestroyImage(magnitude_image);
                 status=MagickFalse;
                 break;
               }
             fourier_image=InverseFourierTransformImage(magnitude_image,
               phase_image,*option == '-' ? MagickTrue : MagickFalse,exception);
+            magnitude_image=DestroyImage(magnitude_image);
+            phase_image=DestroyImage(phase_image);
             if (fourier_image == (Image *) NULL)
               break;
             if (*images != (Image *) NULL)
```
