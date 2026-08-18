# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 905_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `905_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1497-1537 of the vulnerable file.

    */
    if (image_info->number_scenes != 0)
      if (image->scene >= (image_info->scene+image_info->number_scenes-1))
        break;
    offset=(MagickOffsetType) bmp_info.ba_offset;
    if (offset != 0)
      if ((offset < TellBlob(image)) ||
          (SeekBlob(image,offset,SEEK_SET) != offset))
        ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    *magick='\0';
    count=ReadBlob(image,2,magick);
    if ((count == 2) && (IsBMP(magick,2) != MagickFalse))
      {
        /*
          Acquire next image structure.
        */
        AcquireNextImage(image_info,image,exception);
        if (GetNextImageInList(image) == (Image *) NULL)
          {
            status=MagickFalse;
            return((Image *) NULL);
          }
        image=SyncNextImageInList(image);
        status=SetImageProgress(image,LoadImagesTag,TellBlob(image),
          GetBlobSize(image));
        if (status == MagickFalse)
          break;
      }
  } while (IsBMP(magick,2) != MagickFalse);
  (void) CloseBlob(image);
  if (status == MagickFalse)
    return(DestroyImageList(image));
  return(GetFirstImageInList(image));
}


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1514,7 +1514,7 @@
         if (GetNextImageInList(image) == (Image *) NULL)
           {
             status=MagickFalse;
-            return((Image *) NULL);
+            break;
           }
         image=SyncNextImageInList(image);
         status=SetImageProgress(image,LoadImagesTag,TellBlob(image),
```
