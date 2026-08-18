# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2574_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2574_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 150-190 of the vulnerable file.

    ssize_t
      y;

    assert(image_info != (const ImageInfo *) NULL);
    i=0;
    device.cb = sizeof(device);
    image=(Image *) NULL;
    while(EnumDisplayDevices(NULL,i,&device,0) && ++i)
    {
      if ((device.StateFlags & DISPLAY_DEVICE_ACTIVE) != DISPLAY_DEVICE_ACTIVE)
        continue;

      hDC=CreateDC(device.DeviceName,device.DeviceName,NULL,NULL);
      if (hDC == (HDC) NULL)
        ThrowReaderException(CoderError,"UnableToCreateDC");

      screen=AcquireImage(image_info);
      screen->columns=(size_t) GetDeviceCaps(hDC,HORZRES);
      screen->rows=(size_t) GetDeviceCaps(hDC,VERTRES);
      screen->storage_class=DirectClass;
      status=SetImageExtent(screen,screen->columns,screen->rows);
      if (status == MagickFalse)
        {
          InheritException(exception,&image->exception);
          return(DestroyImageList(image));
        }
      if (image == (Image *) NULL)
        image=screen;
      else
        AppendImageToList(&image,screen);

      bitmapDC=CreateCompatibleDC(hDC);
      if (bitmapDC == (HDC) NULL)
        {
          DeleteDC(hDC);
          ThrowReaderException(CoderError,"UnableToCreateDC");
        }
      (void) ResetMagickMemory(&bmi,0,sizeof(BITMAPINFO));
      bmi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
      bmi.bmiHeader.biWidth=(LONG) screen->columns;
      bmi.bmiHeader.biHeight=(-1)*(LONG) screen->rows;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -167,16 +167,16 @@
       screen->columns=(size_t) GetDeviceCaps(hDC,HORZRES);
       screen->rows=(size_t) GetDeviceCaps(hDC,VERTRES);
       screen->storage_class=DirectClass;
-      status=SetImageExtent(screen,screen->columns,screen->rows);
-      if (status == MagickFalse)
-        {
-          InheritException(exception,&image->exception);
-          return(DestroyImageList(image));
-        }
       if (image == (Image *) NULL)
         image=screen;
       else
         AppendImageToList(&image,screen);
+      status=SetImageExtent(screen,screen->columns,screen->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
+        }
 
       bitmapDC=CreateCompatibleDC(hDC);
       if (bitmapDC == (HDC) NULL)
```
