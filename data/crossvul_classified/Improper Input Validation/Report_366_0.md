# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 366_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `366_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 971-1011 of the vulnerable file.

    if (code == 0)
      continue;
    if (code > 0xa1)
      {
        if (image->debug != MagickFalse)
          (void) LogMagickEvent(CoderEvent,GetMagickModule(),"%04X:",code);
      }
    else
      {
        if (image->debug != MagickFalse)
          (void) LogMagickEvent(CoderEvent,GetMagickModule(),
            "  %04X %s: %s",code,codes[code].name,codes[code].description);
        switch (code)
        {
          case 0x01:
          {
            /*
              Clipping rectangle.
            */
            length=ReadBlobMSBShort(image);
            if (length != 0x000a)
              {
                for (i=0; i < (ssize_t) (length-2); i++)
                  if (ReadBlobByte(image) == EOF)
                    break;
                break;
              }
            if (ReadRectangle(image,&frame) == MagickFalse)
              ThrowPICTException(CorruptImageError,"ImproperImageHeader");
            if (((frame.left & 0x8000) != 0) || ((frame.top & 0x8000) != 0))
              break;
            image->columns=(size_t) (frame.right-frame.left);
            image->rows=(size_t) (frame.bottom-frame.top);
            status=SetImageExtent(image,image->columns,image->rows,exception);
            if (status != MagickFalse)
              status=ResetImagePixels(image,exception);
            if (status == MagickFalse)
              return(DestroyImageList(image));
            break;
          }
          case 0x12:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -988,6 +988,9 @@
               Clipping rectangle.
             */
             length=ReadBlobMSBShort(image);
+            if (length > GetBlobSize(image))
+              ThrowPICTException(CorruptImageError,
+                "InsufficientImageDataInFile");
             if (length != 0x000a)
               {
                 for (i=0; i < (ssize_t) (length-2); i++)
@@ -1036,6 +1039,9 @@
             if (pattern != 1)
               ThrowPICTException(CorruptImageError,"UnknownPatternType");
             length=ReadBlobMSBShort(image);
+            if (length > GetBlobSize(image))
+              ThrowPICTException(CorruptImageError,
+                "InsufficientImageDataInFile");
             if (ReadRectangle(image,&frame) == MagickFalse)
               ThrowPICTException(CorruptImageError,"ImproperImageHeader");
             if (ReadPixmap(image,&pixmap) == MagickFalse)
@@ -1047,6 +1053,9 @@
             (void) ReadBlobMSBLong(image);
             flags=(ssize_t) ReadBlobMSBShort(image);
             length=ReadBlobMSBShort(image);
+            if (length > GetBlobSize(image))
+              ThrowPICTException(CorruptImageError,
+                "InsufficientImageDataInFile");
             for (i=0; i <= (ssize_t) length; i++)
               (void) ReadBlobMSBLong(image);
             width=(size_t) (frame.bottom-frame.top);
@@ -1107,6 +1116,9 @@
               Skip polygon or region.
             */
             length=ReadBlobMSBShort(image);
+            if (length > GetBlobSize(image))
+              ThrowPICTException(CorruptImageError,
+                "InsufficientImageDataInFile");
             for (i=0; i < (ssize_t) (length-2); i++)
               if (ReadBlobByte(image) == EOF)
                 break;
@@ -1229,6 +1241,9 @@
                   Skip region.
                 */
                 length=ReadBlobMSBShort(image);
+                if (length > GetBlobSize(image))
+                  ThrowPICTException(CorruptImageError,
+                    "InsufficientImageDataInFile");
                 for (i=0; i < (ssize_t) (length-2); i++)
                   if (ReadBlobByte(image) == EOF)
                     break;
@@ -1351,6 +1366,9 @@
             */
             type=ReadBlobMSBShort(image);
             length=ReadBlobMSBShort(image);
+            if (length > GetBlobSize(image))
+              ThrowPICTException(CorruptImageError,
+                "InsufficientImageDataInFile");
             if (length == 0)
               break;
             (void) ReadBlobMSBLong(image);
@@ -1460,6 +1478,9 @@
             ThrowPICTException(FileOpenError,"UnableToCreateTemporaryFile");
           }
         length=ReadBlobMSBLong(image);
+        if (length > GetBlobSize(image))
+          ThrowPICTException(CorruptImageError,
+            "InsufficientImageDataInFile");
         if (length > 154)
           {
             for (i=0; i < 6; i++)
@@ -1511,6 +1532,9 @@
           Skip reserved.
         */
         length=ReadBlobMSBShort(image);
+        if (length > GetBlobSize(image))
+          ThrowPICTException(CorruptImageError,
+            "InsufficientImageDataInFile");
         for (i=0; i < (ssize_t) length; i++)
           if (ReadBlobByte(image) == EOF)
             break;
@@ -1522,6 +1546,9 @@
           Skip reserved.
         */
         length=(size_t) ((code >> 7) & 0xff);
+        if (length > GetBlobSize(image))
+          ThrowPICTException(CorruptImageError,
+            "InsufficientImageDataInFile");
         for (i=0; i < (ssize_t) length; i++)
           if (ReadBlobByte(image) == EOF)
             break;
```
