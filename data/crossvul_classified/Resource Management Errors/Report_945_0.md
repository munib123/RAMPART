# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 945_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `945_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 7914-7954 of the vulnerable file.

              Mathematically and visually annotate the difference between an
              image and its reconstruction.
            */
            (void) SyncImagesSettings(mogrify_info,*images);
            image=RemoveFirstImageFromList(images);
            reconstruct_image=RemoveFirstImageFromList(images);
            if (reconstruct_image == (Image *) NULL)
              {
                status=MagickFalse;
                break;
              }
            metric=UndefinedMetric;
            option=GetImageOption(image_info,"metric");
            if (option != (const char *) NULL)
              metric=(MetricType) ParseCommandOption(MagickMetricOptions,
                MagickFalse,option);
            difference_image=CompareImageChannels(image,reconstruct_image,
              channel,metric,&distortion,exception);
            if (difference_image == (Image *) NULL)
              break;
            if (*images != (Image *) NULL)
              *images=DestroyImageList(*images);
            *images=difference_image;
            break;
          }
        if (LocaleCompare("complex",option+1) == 0)
          {
            ComplexOperator
              op;

            Image
              *complex_images;

            (void) SyncImageSettings(mogrify_info,*images);
            op=(ComplexOperator) ParseCommandOption(MagickComplexOptions,
              MagickFalse,argv[i+1]);
            complex_images=ComplexImages(*images,op,exception);
            if (complex_images == (Image *) NULL)
              {
                status=MagickFalse;
                break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7931,6 +7931,8 @@
               channel,metric,&distortion,exception);
             if (difference_image == (Image *) NULL)
               break;
+            reconstruct_image=DestroyImage(reconstruct_image);
+            image=DestroyImage(image);
             if (*images != (Image *) NULL)
               *images=DestroyImageList(*images);
             *images=difference_image;
@@ -8273,6 +8275,7 @@
                    q=GetImageFromList(*images,index-1);
                    if (q == (Image *) NULL)
                      {
+                       p=DestroyImage(p);
                        (void) ThrowMagickException(exception,GetMagickModule(),
                          OptionError,"NoSuchImage","`%s'",argv[i+1]);
                        status=MagickFalse;
```
