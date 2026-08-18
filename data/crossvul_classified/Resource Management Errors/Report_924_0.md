# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 924_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `924_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 3858-3898 of the vulnerable file.

      if (LocaleCompare("compare",option+1) == 0)
        {
          double
            distortion;

          Image
            *image,
            *reconstruct_image;

          MetricType
            metric;

          /*
            Mathematically and visually annotate the difference between an
            image and its reconstruction.
          */
          image=RemoveFirstImageFromList(&_images);
          reconstruct_image=RemoveFirstImageFromList(&_images);
          /* FUTURE - produce Exception, rather than silent fail */
          if (reconstruct_image == (Image *) NULL)
            break;
          metric=UndefinedErrorMetric;
          option=GetImageOption(_image_info,"metric");
          if (option != (const char *) NULL)
            metric=(MetricType) ParseCommandOption(MagickMetricOptions,
              MagickFalse,option);
          new_images=CompareImages(image,reconstruct_image,metric,&distortion,
            _exception);
          (void) distortion;
          reconstruct_image=DestroyImage(reconstruct_image);
          image=DestroyImage(image);
          break;
        }
      if (LocaleCompare("complex",option+1) == 0)
        {
          parse=ParseCommandOption(MagickComplexOptions,MagickFalse,arg1);
          if (parse < 0)
            CLIWandExceptArgBreak(OptionError,"UnrecognizedEvaluateOperator",
              option,arg1);
          new_images=ComplexImages(_images,(ComplexOperator) parse,_exception);
          break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3875,7 +3875,10 @@
           reconstruct_image=RemoveFirstImageFromList(&_images);
           /* FUTURE - produce Exception, rather than silent fail */
           if (reconstruct_image == (Image *) NULL)
-            break;
+            { 
+              image=DestroyImage(image);
+              break;
+            }
           metric=UndefinedErrorMetric;
           option=GetImageOption(_image_info,"metric");
           if (option != (const char *) NULL)
```
