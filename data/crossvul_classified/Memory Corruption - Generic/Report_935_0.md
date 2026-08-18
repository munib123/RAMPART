# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 935_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `935_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1753-1793 of the vulnerable file.

        /*
          Convert image to a PBM image.
        */
        (void) SetImageType(image,BilevelType);
        q=pixels;
        for (y=0; y < (ssize_t) image->rows; y++)
        {
          register const PixelPacket
            *magick_restrict p;

          register ssize_t
            x;

          p=GetVirtualPixels(image,0,y,image->columns,1,&image->exception);
          if (p == (const PixelPacket *) NULL)
            break;
          for (x=0; x < (ssize_t) image->columns; x++)
          {
            *q++=(unsigned char) (GetPixelLuma(image,p) >= (QuantumRange/2.0) ?
              '0' : '1');
            *q++=' ';
            if ((q-pixels+1) >= (ssize_t) sizeof(pixels))
              {
                *q++='\n';
                (void) WriteBlob(image,q-pixels,pixels);
                q=pixels;
              }
            p++;
          }
          *q++='\n';
          (void) WriteBlob(image,q-pixels,pixels);
          q=pixels;
          if (image->previous == (Image *) NULL)
            {
              status=SetImageProgress(image,SaveImageTag,(MagickOffsetType) y,
                image->rows);
              if (status == MagickFalse)
                break;
            }
        }
        if (q != pixels)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1770,13 +1770,13 @@
           {
             *q++=(unsigned char) (GetPixelLuma(image,p) >= (QuantumRange/2.0) ?
               '0' : '1');
-            *q++=' ';
             if ((q-pixels+1) >= (ssize_t) sizeof(pixels))
               {
                 *q++='\n';
                 (void) WriteBlob(image,q-pixels,pixels);
                 q=pixels;
               }
+            *q++=' ';
             p++;
           }
           *q++='\n';
```
