# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1018_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1018_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 4073-4110 of the vulnerable file.

            break;
          (void) ExportQuantumPixels(image,(const CacheView *) NULL,
            quantum_info,quantum_type,pixels,&image->exception);
          if (TIFFWritePixels(tiff,&tiff_info,y,0,image) == -1)
            break;
          if (image->previous == (Image *) NULL)
            {
              status=SetImageProgress(image,SaveImageTag,(MagickOffsetType) y,
                image->rows);
              if (status == MagickFalse)
                break;
            }
        }
        break;
      }
    }
    quantum_info=DestroyQuantumInfo(quantum_info);
    if (image->colorspace == LabColorspace)
      DecodeLabImage(image,&image->exception);
    DestroyTIFFInfo(&tiff_info);
    if (image->exception.severity > ErrorException)
      break;
DisableMSCWarning(4127)
    if (0 && (image_info->verbose != MagickFalse))
RestoreMSCWarning
      TIFFPrintDirectory(tiff,stdout,MagickFalse);
    (void) TIFFWriteDirectory(tiff);
    image=SyncNextImageInList(image);
    if (image == (Image *) NULL)
      break;
    status=SetImageProgress(image,SaveImagesTag,scene++,imageListLength);
    if (status == MagickFalse)
      break;
  } while (image_info->adjoin != MagickFalse);
  TIFFClose(tiff);
  return(image->exception.severity > ErrorException ? MagickFalse : MagickTrue);
}
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4090,13 +4090,15 @@
     if (image->colorspace == LabColorspace)
       DecodeLabImage(image,&image->exception);
     DestroyTIFFInfo(&tiff_info);
-    if (image->exception.severity > ErrorException)
-      break;
 DisableMSCWarning(4127)
     if (0 && (image_info->verbose != MagickFalse))
 RestoreMSCWarning
       TIFFPrintDirectory(tiff,stdout,MagickFalse);
-    (void) TIFFWriteDirectory(tiff);
+    if (TIFFWriteDirectory(tiff) == 0)
+      {
+        status=MagickFalse;
+        break;
+      }
     image=SyncNextImageInList(image);
     if (image == (Image *) NULL)
       break;
@@ -4105,6 +4107,6 @@
       break;
   } while (image_info->adjoin != MagickFalse);
   TIFFClose(tiff);
-  return(image->exception.severity > ErrorException ? MagickFalse : MagickTrue);
+  return(status);
 }
 #endif
```
