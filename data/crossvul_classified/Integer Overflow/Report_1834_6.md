# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1834_6
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1834_6`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1629-1669 of the vulnerable file.

    pixmap;

  PICTRectangle
    bounds,
    crop_rectangle,
    destination_rectangle,
    frame_rectangle,
    size_rectangle,
    source_rectangle;

  register const Quantum
    *p;

  register ssize_t
    i,
    x;

  size_t
    bytes_per_line,
    count,
    storage_class;

  ssize_t
    y;

  unsigned char
    *buffer,
    *packed_scanline,
    *scanline;

  unsigned short
    base_address,
    row_bytes,
    transfer_mode;

  /*
    Open output image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  assert(image != (Image *) NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1646,6 +1646,7 @@
   size_t
     bytes_per_line,
     count,
+    row_bytes,
     storage_class;
 
   ssize_t
@@ -1658,7 +1659,6 @@
 
   unsigned short
     base_address,
-    row_bytes,
     transfer_mode;
 
   /*
@@ -1690,7 +1690,7 @@
   source_rectangle=size_rectangle;
   destination_rectangle=size_rectangle;
   base_address=0xff;
-  row_bytes=(unsigned short) (image->columns | 0x8000);
+  row_bytes=image->columns;
   bounds.top=0;
   bounds.left=0;
   bounds.bottom=(short) image->rows;
@@ -1720,7 +1720,7 @@
       pixmap.bits_per_pixel=32;
       pixmap.pack_type=0x04;
       transfer_mode=0x40;
-      row_bytes=(unsigned short) ((4*image->columns) | 0x8000);
+      row_bytes=4*image->columns;
     }
   /*
     Allocate memory.
```
