# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2829_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2829_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 198-238 of the vulnerable file.

          GetQuantumPixels(quantum_info),&count);
        if (count != (ssize_t) length)
          break;
      }
    }
  count=0;
  length=0;
  scene=0;
  do
  {
    /*
      Read pixels to virtual canvas image then push to image.
    */
    if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
      if (image->scene >= (image_info->scene+image_info->number_scenes-1))
        break;
    status=SetImageExtent(image,image->columns,image->rows,exception);
    if (status == MagickFalse)
    {
      quantum_info=DestroyQuantumInfo(quantum_info);
      return(DestroyImageList(image));
    }
    SetImageColorspace(image,YCbCrColorspace,exception);
    switch (image_info->interlace)
    {
      case NoInterlace:
      default:
      {
        /*
          No interlacing:  YCbCrYCbCrYCbCrYCbCrYCbCrYCbCr...
        */
        if (scene == 0)
          {
            length=GetQuantumExtent(canvas_image,quantum_info,quantum_type);
            pixels=(const unsigned char *) ReadBlobStream(image,length,
              GetQuantumPixels(quantum_info),&count);
          }
        for (y=0; y < (ssize_t) image->extract_info.height; y++)
        {
          if (count != (ssize_t) length)
            {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -215,6 +215,7 @@
     if (status == MagickFalse)
     {
       quantum_info=DestroyQuantumInfo(quantum_info);
+      canvas_image=DestroyImage(canvas_image);
       return(DestroyImageList(image));
     }
     SetImageColorspace(image,YCbCrColorspace,exception);
```
