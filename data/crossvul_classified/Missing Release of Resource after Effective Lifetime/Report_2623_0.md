# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2623_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2623_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 554-592 of the vulnerable file.


      (void) ParseGeometry(image_info->density,&geometry_info);
      density=(size_t) floor(geometry_info.rho+0.5);
    }
  (void) FormatLocaleString(header,sizeof(header),"rdensty: %04lu",
    (unsigned long) density);
  count=WriteCALSRecord(image,header);
  count=WriteCALSRecord(image,"notes: NONE");
  (void) ResetMagickMemory(header,' ',128);
  for (i=0; i < 5; i++)
    (void) WriteBlob(image,128,(unsigned char *) header);
  /*
    Write CALS pixels.
  */
  write_info=CloneImageInfo(image_info);
  (void) CopyMagickString(write_info->filename,"GROUP4:",MaxTextExtent);
  (void) CopyMagickString(write_info->magick,"GROUP4",MaxTextExtent);
  group4_image=CloneImage(image,0,0,MagickTrue,&image->exception);
  if (group4_image == (Image *) NULL)
    {
      (void) CloseBlob(image);
      return(MagickFalse);
    }
  group4=(unsigned char *) ImageToBlob(write_info,group4_image,&length,
    &image->exception);
  group4_image=DestroyImage(group4_image);
  if (group4 == (unsigned char *) NULL)
    {
      (void) CloseBlob(image);
      return(MagickFalse);
    }
  write_info=DestroyImageInfo(write_info);
  if (WriteBlob(image,length,group4) != (ssize_t) length)
    status=MagickFalse;
  group4=(unsigned char *) RelinquishMagickMemory(group4);
  (void) CloseBlob(image);
  return(status);
}
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -571,6 +571,7 @@
   group4_image=CloneImage(image,0,0,MagickTrue,&image->exception);
   if (group4_image == (Image *) NULL)
     {
+      write_info=DestroyImageInfo(write_info);
       (void) CloseBlob(image);
       return(MagickFalse);
     }
@@ -579,6 +580,7 @@
   group4_image=DestroyImage(group4_image);
   if (group4 == (unsigned char *) NULL)
     {
+      write_info=DestroyImageInfo(write_info);
       (void) CloseBlob(image);
       return(MagickFalse);
     }
```
