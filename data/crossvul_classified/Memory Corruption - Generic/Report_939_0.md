# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 939_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `939_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1823-1863 of the vulnerable file.


          p=GetVirtualPixels(image,0,y,image->columns,1,&image->exception);
          if (p == (const PixelPacket *) NULL)
            break;
          for (x=0; x < (ssize_t) image->columns; x++)
          {
            index=ClampToQuantum(GetPixelLuma(image,p));
            if (image->depth <= 8)
              count=(ssize_t) FormatLocaleString(buffer,MaxTextExtent,"%u ",
                ScaleQuantumToChar(index));
            else
              if (image->depth <= 16)
                count=(ssize_t) FormatLocaleString(buffer,MaxTextExtent,"%u ",
                  ScaleQuantumToShort(index));
              else
                count=(ssize_t) FormatLocaleString(buffer,MaxTextExtent,"%u ",
                  ScaleQuantumToLong(index));
            extent=(size_t) count;
            (void) strncpy((char *) q,buffer,extent);
            q+=extent;
            if ((q-pixels+extent+1) >= sizeof(pixels))
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
          {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1840,7 +1840,7 @@
             extent=(size_t) count;
             (void) strncpy((char *) q,buffer,extent);
             q+=extent;
-            if ((q-pixels+extent+1) >= sizeof(pixels))
+            if ((q-pixels+extent+2) >= sizeof(pixels))
               {
                 *q++='\n';
                 (void) WriteBlob(image,q-pixels,pixels);
@@ -1915,7 +1915,7 @@
             extent=(size_t) count;
             (void) strncpy((char *) q,buffer,extent);
             q+=extent;
-            if ((q-pixels+extent+1) >= sizeof(pixels))
+            if ((q-pixels+extent+2) >= sizeof(pixels))
               {
                 *q++='\n';
                 (void) WriteBlob(image,q-pixels,pixels);
```
