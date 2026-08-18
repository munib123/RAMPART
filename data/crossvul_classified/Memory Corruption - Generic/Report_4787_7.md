# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4787_7
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4787_7`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 122-162 of the vulnerable file.


  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickSignature);
  image=AcquireImage(image_info);
  {
    HBITMAP
      bitmapH;

    HPALETTE
      hPal;

    OpenClipboard(NULL);
    bitmapH=(HBITMAP) GetClipboardData(CF_BITMAP);
    hPal=(HPALETTE) GetClipboardData(CF_PALETTE);
    CloseClipboard();
    if ( bitmapH == NULL )
      ThrowReaderException(CoderError,"NoBitmapOnClipboard");
    {
      BITMAPINFO
        DIBinfo;

      BITMAP
        bitmap;

      HBITMAP
        hBitmap,
        hOldBitmap;

      HDC
        hDC,
        hMemDC;

      RGBQUAD
        *pBits,
        *ppBits;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -139,7 +139,7 @@
     bitmapH=(HBITMAP) GetClipboardData(CF_BITMAP);
     hPal=(HPALETTE) GetClipboardData(CF_PALETTE);
     CloseClipboard();
-    if ( bitmapH == NULL )
+    if (bitmapH == NULL)
       ThrowReaderException(CoderError,"NoBitmapOnClipboard");
     {
       BITMAPINFO
@@ -166,8 +166,14 @@
       GetObject(bitmapH,sizeof(BITMAP),(LPSTR) &bitmap);
       if ((image->columns == 0) || (image->rows == 0))
         {
+          image->columns=bitmap.bmWidth;
           image->rows=bitmap.bmHeight;
-          image->columns=bitmap.bmWidth;
+        }
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
         }
       /*
         Initialize the bitmap header info.
```
