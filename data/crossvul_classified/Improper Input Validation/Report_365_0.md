# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 365_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `365_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 3840-3880 of the vulnerable file.

            filename[MagickPathExtent];

          const char
            *property;

          FILE
            *file;

          Image
            *jpeg_image;

          int
            unique_file;

          unsigned int
            tag;

          tag=((unsigned int) ReadBlobLSBShort(image) << 16) |
            ReadBlobLSBShort(image);
          length=(size_t) ReadBlobLSBLong(image);
          if (tag == 0xFFFEE0DD)
            break; /* sequence delimiter tag */
          if (tag != 0xFFFEE000)
            {
              read_info=DestroyImageInfo(read_info);
              ThrowDCMException(CorruptImageError,"ImproperImageHeader");
            }
          file=(FILE *) NULL;
          unique_file=AcquireUniqueFileResource(filename);
          if (unique_file != -1)
            file=fdopen(unique_file,"wb");
          if (file == (FILE *) NULL)
            {
              (void) RelinquishUniqueFileResource(filename);
              ThrowFileException(exception,FileOpenError,
                "UnableToCreateTemporaryFile",filename);
              break;
            }
          for (c=EOF; length != 0; length--)
          {
            c=ReadBlobByte(image);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3857,6 +3857,8 @@
           tag=((unsigned int) ReadBlobLSBShort(image) << 16) |
             ReadBlobLSBShort(image);
           length=(size_t) ReadBlobLSBLong(image);
+          if (length > (size_t) GetBlobSize(image))
+            ThrowDCMException(CorruptImageError,"InsufficientImageDataInFile");
           if (tag == 0xFFFEE0DD)
             break; /* sequence delimiter tag */
           if (tag != 0xFFFEE000)
```
