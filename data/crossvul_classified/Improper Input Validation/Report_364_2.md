# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 364_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `364_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1461-1501 of the vulnerable file.

          }
        length=ReadBlobMSBLong(image);
        if (length > 154)
          {
            for (i=0; i < 6; i++)
              (void) ReadBlobMSBLong(image);
            if (ReadRectangle(image,&frame) == MagickFalse)
              {
                (void) fclose(file);
                (void) RelinquishUniqueFileResource(read_info->filename);
                ThrowPICTException(CorruptImageError,"ImproperImageHeader");
              }
            for (i=0; i < 122; i++)
              if (ReadBlobByte(image) == EOF)
                break;
            for (i=0; i < (ssize_t) (length-154); i++)
            {
              c=ReadBlobByte(image);
              if (c == EOF)
                break;
              (void) fputc(c,file);
            }
          }
        (void) fclose(file);
        (void) close(unique_file);
        tile_image=ReadImage(read_info,exception);
        (void) RelinquishUniqueFileResource(filename);
        read_info=DestroyImageInfo(read_info);
        if (tile_image == (Image *) NULL)
          continue;
        (void) FormatLocaleString(geometry,MagickPathExtent,"%.20gx%.20g",
          (double) MagickMax(image->columns,tile_image->columns),
          (double) MagickMax(image->rows,tile_image->rows));
        (void) SetImageExtent(image,
          MagickMax(image->columns,tile_image->columns),
          MagickMax(image->rows,tile_image->rows),exception);
        (void) TransformImageColorspace(image,tile_image->colorspace,exception);
        (void) CompositeImage(image,tile_image,CopyCompositeOp,MagickTrue,
          (ssize_t) frame.left,(ssize_t) frame.right,exception);
        image->compression=tile_image->compression;
        tile_image=DestroyImage(tile_image);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1478,7 +1478,8 @@
               c=ReadBlobByte(image);
               if (c == EOF)
                 break;
-              (void) fputc(c,file);
+              if (fputc(c,file) != c)
+                break;
             }
           }
         (void) fclose(file);
```
