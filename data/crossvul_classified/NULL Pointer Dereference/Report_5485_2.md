# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5485_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5485_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 784-825 of the vulnerable file.

            /*
              Sparse-color format.
            */
            if (GetPixelAlpha(image,p) == (Quantum) OpaqueAlpha)
              {
                GetColorTuple(&pixel,MagickFalse,tuple);
                (void) FormatLocaleString(buffer,MagickPathExtent,
                  "%.20g,%.20g,",(double) x,(double) y);
                (void) WriteBlobString(image,buffer);
                (void) WriteBlobString(image,tuple);
                (void) WriteBlobString(image," ");
              }
            p+=GetPixelChannels(image);
            continue;
          }
        (void) FormatLocaleString(buffer,MagickPathExtent,"%.20g,%.20g: ",
          (double) x,(double) y);
        (void) WriteBlobString(image,buffer);
        (void) CopyMagickString(tuple,"(",MagickPathExtent);
        if (pixel.colorspace == GRAYColorspace)
          ConcatenateColorComponent(&pixel,GrayPixelChannel,compliance,
            tuple);
        else
          {
            ConcatenateColorComponent(&pixel,RedPixelChannel,compliance,tuple);
            (void) ConcatenateMagickString(tuple,",",MagickPathExtent);
            ConcatenateColorComponent(&pixel,GreenPixelChannel,compliance,
              tuple);
            (void) ConcatenateMagickString(tuple,",",MagickPathExtent);
            ConcatenateColorComponent(&pixel,BluePixelChannel,compliance,tuple);
          }
        if (pixel.colorspace == CMYKColorspace)
          {
            (void) ConcatenateMagickString(tuple,",",MagickPathExtent);
            ConcatenateColorComponent(&pixel,BlackPixelChannel,compliance,
              tuple);
          }
        if (pixel.alpha_trait != UndefinedPixelTrait)
          {
            (void) ConcatenateMagickString(tuple,",",MagickPathExtent);
            ConcatenateColorComponent(&pixel,AlphaPixelChannel,compliance,
              tuple);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -801,8 +801,7 @@
         (void) WriteBlobString(image,buffer);
         (void) CopyMagickString(tuple,"(",MagickPathExtent);
         if (pixel.colorspace == GRAYColorspace)
-          ConcatenateColorComponent(&pixel,GrayPixelChannel,compliance,
-            tuple);
+          ConcatenateColorComponent(&pixel,GrayPixelChannel,compliance,tuple);
         else
           {
             ConcatenateColorComponent(&pixel,RedPixelChannel,compliance,tuple);
```
