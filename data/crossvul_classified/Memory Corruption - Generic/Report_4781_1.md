# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4781_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4781_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1877-1919 of the vulnerable file.

          if (image->previous == (Image *) NULL)
            {
              status=SetImageProgress(image,LoadImageTag,(MagickOffsetType) y,
                image->rows);
              if (status == MagickFalse)
                break;
            }
        }
        break;
      }
      case ReadTileMethod:
      {
        register uint32
          *p;

        uint32
          *tile_pixels,
          columns,
          rows;

        size_t
          number_pixels;

        /*
          Convert tiled TIFF image to DirectClass MIFF image.
        */
        if ((TIFFGetField(tiff,TIFFTAG_TILEWIDTH,&columns) != 1) ||
            (TIFFGetField(tiff,TIFFTAG_TILELENGTH,&rows) != 1))
          {
            TIFFClose(tiff);
            ThrowReaderException(CoderError,"ImageIsNotTiled");
          }
        (void) SetImageStorageClass(image,DirectClass);
        number_pixels=columns*rows;
        tile_pixels=(uint32 *) AcquireQuantumMemory(number_pixels,
          sizeof(*tile_pixels));
        if (tile_pixels == (uint32 *) NULL)
          {
            TIFFClose(tiff);
            ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
          }
        for (y=0; y < (ssize_t) image->rows; y+=rows)
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1894,9 +1894,6 @@
           columns,
           rows;
 
-        size_t
-          number_pixels;
-
         /*
           Convert tiled TIFF image to DirectClass MIFF image.
         */
@@ -1907,7 +1904,13 @@
             ThrowReaderException(CoderError,"ImageIsNotTiled");
           }
         (void) SetImageStorageClass(image,DirectClass);
-        number_pixels=columns*rows;
+        number_pixels=(MagickSizeType) columns*rows;
+        if ((number_pixels*sizeof(uint32)) != (MagickSizeType) ((size_t)
+            (number_pixels*sizeof(uint32))))
+          {
+            TIFFClose(tiff);
+            ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+          }
         tile_pixels=(uint32 *) AcquireQuantumMemory(number_pixels,
           sizeof(*tile_pixels));
         if (tile_pixels == (uint32 *) NULL)
```
