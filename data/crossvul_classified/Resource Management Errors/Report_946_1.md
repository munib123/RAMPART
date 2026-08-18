# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 946_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `946_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 3811-3851 of the vulnerable file.

        }
      CLIWandExceptionBreak(OptionError,"UnrecognizedOption",option);
    }
    case 'c':
    {
      if (LocaleCompare("channel-fx",option+1) == 0)
        {
          new_images=ChannelFxImage(_images,arg1,_exception);
          break;
        }
      if (LocaleCompare("clut",option+1) == 0)
        {
          Image
            *clut_image;

          /* FUTURE - make this a compose option, and thus can be used
             with layers compose or even compose last image over all other
             _images.
          */
          new_images=RemoveFirstImageFromList(&_images);
          clut_image=RemoveLastImageFromList(&_images);
          /* FUTURE - produce Exception, rather than silent fail */
          if (clut_image == (Image *) NULL)
            break;
          (void) ClutImage(new_images,clut_image,new_images->interpolate,
            _exception);
          clut_image=DestroyImage(clut_image);
          break;
        }
      if (LocaleCompare("coalesce",option+1) == 0)
        {
          new_images=CoalesceImages(_images,_exception);
          break;
        }
      if (LocaleCompare("combine",option+1) == 0)
        {
          parse=(ssize_t) _images->colorspace;
          if (_images->number_channels < GetImageListLength(_images))
            parse=sRGBColorspace;
          if ( IfPlusOp )
            parse=ParseCommandOption(MagickColorspaceOptions,MagickFalse,arg1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3828,10 +3828,16 @@
              _images.
           */
           new_images=RemoveFirstImageFromList(&_images);
-          clut_image=RemoveLastImageFromList(&_images);
+          clut_image=RemoveFirstImageFromList(&_images);
           /* FUTURE - produce Exception, rather than silent fail */
           if (clut_image == (Image *) NULL)
-            break;
+            {
+              (void) ThrowMagickException(_exception,GetMagickModule(),
+                OptionError,"ImageSequenceRequired","`%s'",option);
+              new_images=DestroyImage(new_images);
+              status=MagickFalse;
+              break;
+            }
           (void) ClutImage(new_images,clut_image,new_images->interpolate,
             _exception);
           clut_image=DestroyImage(clut_image);
@@ -3875,8 +3881,11 @@
           reconstruct_image=RemoveFirstImageFromList(&_images);
           /* FUTURE - produce Exception, rather than silent fail */
           if (reconstruct_image == (Image *) NULL)
-            { 
+            {
+              (void) ThrowMagickException(_exception,GetMagickModule(),
+                OptionError,"ImageSequenceRequired","`%s'",option);
               image=DestroyImage(image);
+              status=MagickFalse;
               break;
             }
           metric=UndefinedErrorMetric;
@@ -3938,7 +3947,13 @@
           new_images=RemoveFirstImageFromList(&_images);
           source_image=RemoveFirstImageFromList(&_images);
           if (source_image == (Image *) NULL)
-            break; /* FUTURE - produce Exception, rather than silent fail */
+            {
+              (void) ThrowMagickException(_exception,GetMagickModule(),
+                OptionError,"ImageSequenceRequired","`%s'",option);
+              new_images=DestroyImage(new_images);
+              status=MagickFalse;
+              break;
+            }
 
           /* FUTURE - this should not be here! - should be part of -geometry */
           if (source_image->geometry != (char *) NULL)
@@ -4128,7 +4143,13 @@
           new_images=RemoveFirstImageFromList(&_images);
           hald_image=RemoveLastImageFromList(&_images);
           if (hald_image == (Image *) NULL)
-            break;
+            {
+              (void) ThrowMagickException(_exception,GetMagickModule(),
+                OptionError,"ImageSequenceRequired","`%s'",option);
+              new_images=DestroyImage(new_images);
+              status=MagickFalse;
+              break;
+            }
           (void) HaldClutImage(new_images,hald_image,_exception);
           hald_image=DestroyImage(hald_image);
           break;
@@ -4143,15 +4164,20 @@
             *magnitude_image,
             *phase_image;
 
-           magnitude_image=RemoveFirstImageFromList(&_images);
-           phase_image=RemoveFirstImageFromList(&_images);
-          /* FUTURE - produce Exception, rather than silent fail */
-           if (phase_image == (Image *) NULL)
-             break;
-           new_images=InverseFourierTransformImage(magnitude_image,phase_image,
-             IsNormalOp,_exception);
-           magnitude_image=DestroyImage(magnitude_image);
-           phase_image=DestroyImage(phase_image);
+          magnitude_image=RemoveFirstImageFromList(&_images);
+          phase_image=RemoveFirstImageFromList(&_images);
+          if (phase_image == (Image *) NULL)
+            {
+              (void) ThrowMagickException(_exception,GetMagickModule(),
+                OptionError,"ImageSequenceRequired","`%s'",option);
+              magnitude_image=DestroyImage(magnitude_image);
+              status=MagickFalse;
+              break;
+            }
+          new_images=InverseFourierTransformImage(magnitude_image,phase_image,
+            IsNormalOp,_exception);
+          magnitude_image=DestroyImage(magnitude_image);
+          phase_image=DestroyImage(phase_image);
           break;
         }
       if (LocaleCompare("insert",option+1) == 0)
```
