# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 844_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `844_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 6947-6987 of the vulnerable file.

  char *end = CharBuf + length;
  static const
  unsigned char ExifHeader[] = {0x45, 0x78, 0x69, 0x66, 0x00, 0x00};
  CHECK_BUFFER(CharBuf+2, end, 6);
  if (length <= 8 || memcmp(CharBuf+2, ExifHeader, 6)) {
    raise_warning("Incorrect APP1 Exif Identifier Code");
    return;
  }
  exif_process_TIFF_in_JPEG(ImageInfo, CharBuf + 8, length - 8,
                            displacement+8);
}

/* Process an JPEG APP12 block marker used by OLYMPUS */
static void exif_process_APP12(image_info_type *ImageInfo,
                               char *buffer, size_t length) {
  size_t l1, l2=0;
  if ((l1 = php_strnlen(buffer+2, length-2)) > 0) {
    exif_iif_add_tag(ImageInfo, SECTION_APP12, "Company",
                     TAG_NONE, TAG_FMT_STRING, l1, buffer+2);
    if (length > 2+l1+1) {
      l2 = php_strnlen(buffer+2+l1+1, length-2-l1+1);
      exif_iif_add_tag(ImageInfo, SECTION_APP12, "Info",
                       TAG_NONE, TAG_FMT_STRING, l2, buffer+2+l1+1);
    }
  }
}

/* Process a SOFn marker.  This is useful for the image dimensions */
static void
exif_process_SOFn(unsigned char* Data, int /*marker*/, jpeg_sof_info* result) {
  result->bits_per_sample = Data[2];
  result->height          = php_jpg_get16(Data+3);
  result->width           = php_jpg_get16(Data+5);
  result->num_components  = Data[7];
}

/* Parse the marker stream until SOS or EOI is seen; */
static int exif_scan_JPEG_header(image_info_type *ImageInfo) {
  int section, sn;
  int marker = 0, last_marker = M_PSEUDO, comment_correction=1;
  int ll, lh;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6964,7 +6964,7 @@
     exif_iif_add_tag(ImageInfo, SECTION_APP12, "Company",
                      TAG_NONE, TAG_FMT_STRING, l1, buffer+2);
     if (length > 2+l1+1) {
-      l2 = php_strnlen(buffer+2+l1+1, length-2-l1+1);
+      l2 = php_strnlen(buffer+2+l1+1, length-2-l1-1);
       exif_iif_add_tag(ImageInfo, SECTION_APP12, "Info",
                        TAG_NONE, TAG_FMT_STRING, l2, buffer+2+l1+1);
     }
```
