# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 938_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `938_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1817-1857 of the vulnerable file.


          p=GetVirtualPixels(image,0,y,image->columns,1,exception);
          if (p == (const Quantum *) NULL)
            break;
          for (x=0; x < (ssize_t) image->columns; x++)
          {
            index=ClampToQuantum(GetPixelLuma(image,p));
            if (image->depth <= 8)
              count=(ssize_t) FormatLocaleString(buffer,MagickPathExtent,"%u ",
                ScaleQuantumToChar(index));
            else
              if (image->depth <= 16)
                count=(ssize_t) FormatLocaleString(buffer,MagickPathExtent,
                  "%u ",ScaleQuantumToShort(index));
              else
                count=(ssize_t) FormatLocaleString(buffer,MagickPathExtent,
                  "%u ",ScaleQuantumToLong(index));
            extent=(size_t) count;
            (void) strncpy((char *) q,buffer,extent);
            q+=extent;
            if ((q-pixels+extent+1) >= sizeof(pixels))
              {
                *q++='\n';
                (void) WriteBlob(image,q-pixels,pixels);
                q=pixels;
              }
            p+=GetPixelChannels(image);
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
          {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1834,7 +1834,7 @@
             extent=(size_t) count;
             (void) strncpy((char *) q,buffer,extent);
             q+=extent;
-            if ((q-pixels+extent+1) >= sizeof(pixels))
+            if ((q-pixels+extent+2) >= sizeof(pixels))
               {
                 *q++='\n';
                 (void) WriteBlob(image,q-pixels,pixels);
@@ -1909,7 +1909,7 @@
             extent=(size_t) count;
             (void) strncpy((char *) q,buffer,extent);
             q+=extent;
-            if ((q-pixels+extent+1) >= sizeof(pixels))
+            if ((q-pixels+extent+2) >= sizeof(pixels))
               {
                 *q++='\n';
                 (void) WriteBlob(image,q-pixels,pixels);
```
