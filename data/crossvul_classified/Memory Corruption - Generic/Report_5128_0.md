# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5128_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5128_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1100-1140 of the vulnerable file.

              BitmapHeader2.HorzRes=ReadBlobLSBShort(image);
              BitmapHeader2.VertRes=ReadBlobLSBShort(image);

              image->units=PixelsPerCentimeterResolution;
              image->page.width=(unsigned int)
                ((BitmapHeader2.LowLeftX-BitmapHeader2.UpRightX)/470.0);
              image->page.height=(unsigned int)
                ((BitmapHeader2.LowLeftX-BitmapHeader2.UpRightY)/470.0);
              image->page.x=(int) (BitmapHeader2.LowLeftX/470.0);
              image->page.y=(int) (BitmapHeader2.LowLeftX/470.0);
              if(BitmapHeader2.HorzRes && BitmapHeader2.VertRes)
                {
                  image->resolution.x=BitmapHeader2.HorzRes/470.0;
                  image->resolution.y=BitmapHeader2.VertRes/470.0;
                }
              image->columns=BitmapHeader2.Width;
              image->rows=BitmapHeader2.Height;
              bpp=BitmapHeader2.Depth;

            UnpackRaster:      
              if ((image->colors == 0) && (bpp != 24))
                {
                  image->colors=one << bpp;
                  if (!AcquireImageColormap(image,image->colors,exception))
                    {
                    NoMemory:
                      ThrowReaderException(ResourceLimitError,
                        "MemoryAllocationFailed");
                    }
                  /* printf("Load default colormap \n"); */
                  for (i=0; (i < (int) image->colors) && (i < 256); i++)
                    {               
                      image->colormap[i].red=ScaleCharToQuantum(WPG1_Palette[i].Red);
                      image->colormap[i].green=ScaleCharToQuantum(WPG1_Palette[i].Green);
                      image->colormap[i].blue=ScaleCharToQuantum(WPG1_Palette[i].Blue);
                    }
                }
              else
                {
                  if (bpp < 24)
                    if ( (image->colors < (one << bpp)) && (bpp != 24) )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1117,6 +1117,9 @@
               bpp=BitmapHeader2.Depth;
 
             UnpackRaster:      
+              status=SetImageExtent(image,image->columns,image->rows,exception);
+              if (status == MagickFalse)
+                break;
               if ((image->colors == 0) && (bpp != 24))
                 {
                   image->colors=one << bpp;
@@ -1310,6 +1313,9 @@
                 }
               image->columns=Bitmap2Header1.Width;
               image->rows=Bitmap2Header1.Height;
+              status=SetImageExtent(image,image->columns,image->rows,exception);
+              if (status == MagickFalse)
+                break;
 
               if ((image->colors == 0) && (bpp != 24))
                 {
@@ -1428,9 +1434,6 @@
          ThrowReaderException(CoderError,"DataEncodingSchemeIsNotSupported");
       }
    }
-  status=SetImageExtent(image,image->columns,image->rows,exception);
-  if (status == MagickFalse)
-    return(DestroyImageList(image));
 
  Finish:
   (void) CloseBlob(image);
```
