# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 947_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `947_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 7835-7875 of the vulnerable file.

          {
            if (*option == '+')
              {
                channel=DefaultChannels;
                break;
              }
            channel=(ChannelType) ParseChannelOption(argv[i+1]);
            break;
          }
        if (LocaleCompare("clut",option+1) == 0)
          {
            Image
              *clut_image,
              *image;

            (void) SyncImagesSettings(mogrify_info,*images);
            image=RemoveFirstImageFromList(images);
            clut_image=RemoveFirstImageFromList(images);
            if (clut_image == (Image *) NULL)
              {
                status=MagickFalse;
                break;
              }
            (void) ClutImageChannel(image,channel,clut_image);
            clut_image=DestroyImage(clut_image);
            InheritException(exception,&image->exception);
            *images=DestroyImageList(*images);
            *images=image;
            break;
          }
        if (LocaleCompare("coalesce",option+1) == 0)
          {
            Image
              *coalesce_image;

            (void) SyncImagesSettings(mogrify_info,*images);
            coalesce_image=CoalesceImages(*images,exception);
            if (coalesce_image == (Image *) NULL)
              {
                status=MagickFalse;
                break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7852,6 +7852,9 @@
             clut_image=RemoveFirstImageFromList(images);
             if (clut_image == (Image *) NULL)
               {
+                (void) ThrowMagickException(exception,GetMagickModule(),
+                  OptionError,"ImageSequenceRequired","`%s'",option);
+                image=DestroyImage(image);
                 status=MagickFalse;
                 break;
               }
@@ -7896,9 +7899,6 @@
           }
         if (LocaleCompare("compare",option+1) == 0)
           {
-            const char
-              *option;
-
             double
               distortion;
 
@@ -7919,6 +7919,9 @@
             reconstruct_image=RemoveFirstImageFromList(images);
             if (reconstruct_image == (Image *) NULL)
               {
+                (void) ThrowMagickException(exception,GetMagickModule(),
+                  OptionError,"ImageSequenceRequired","`%s'",option);
+                image=DestroyImage(image);
                 status=MagickFalse;
                 break;
               }
@@ -7974,6 +7977,9 @@
             composite_image=RemoveFirstImageFromList(images);
             if (composite_image == (Image *) NULL)
               {
+                (void) ThrowMagickException(exception,GetMagickModule(),
+                  OptionError,"ImageSequenceRequired","`%s'",option);
+                image=DestroyImage(image);
                 status=MagickFalse;
                 break;
               }
@@ -8205,6 +8211,9 @@
             hald_image=RemoveFirstImageFromList(images);
             if (hald_image == (Image *) NULL)
               {
+                (void) ThrowMagickException(exception,GetMagickModule(),
+                  OptionError,"ImageSequenceRequired","`%s'",option);
+                image=DestroyImage(image);
                 status=MagickFalse;
                 break;
               }
@@ -8235,11 +8244,16 @@
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
