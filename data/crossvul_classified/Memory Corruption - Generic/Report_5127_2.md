# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5127_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5127_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1299-1339 of the vulnerable file.

                case 2:
                  bpp=2;
                  break;
                case 3:
                  bpp=4;
                  break;
                case 4:
                  bpp=8;
                  break;
                case 8:
                  bpp=24;
                  break;
                default:
                  continue;  /*Ignore raster with unknown depth*/
                }
              image->columns=Bitmap2Header1.Width;
              image->rows=Bitmap2Header1.Height;
              status=SetImageExtent(image,image->columns,image->rows,exception);
              if (status == MagickFalse)
                break;

              if ((image->colors == 0) && (bpp != 24))
                {
                  size_t
                    one;

                  one=1;
                  image->colors=one << bpp;
                  if (!AcquireImageColormap(image,image->colors,exception))
                    goto NoMemory;
                }
              else
                {
                  if(bpp < 24)
                    if( image->colors<(one << bpp) && bpp!=24 )
                      image->colormap=(PixelInfo *) ResizeQuantumMemory(
                       image->colormap,(size_t) (one << bpp),
                       sizeof(*image->colormap));
                }


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1316,7 +1316,6 @@
               status=SetImageExtent(image,image->columns,image->rows,exception);
               if (status == MagickFalse)
                 break;
-
               if ((image->colors == 0) && (bpp != 24))
                 {
                   size_t
```
