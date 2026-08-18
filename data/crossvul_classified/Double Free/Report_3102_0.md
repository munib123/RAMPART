# CrossVul Fix Pair: Double Free in c
**Pair ID:** 3102_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3102_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 2066-2106 of the vulnerable file.

        break;
      (void) AddValueToSplayTree(exif_resources,q,q);
      tag_value=(ssize_t) ReadProfileShort(endian,q);
      format=(ssize_t) ReadProfileShort(endian,q+2);
      if ((format < 0) || ((format-1) >= EXIF_NUM_FORMATS))
        break;
      components=(ssize_t) ReadProfileLong(endian,q+4);
      if (components < 0)
        break;  /* corrupt EXIF */
      number_bytes=(size_t) components*format_bytes[format];
      if ((ssize_t) number_bytes < components)
        break;  /* prevent overflow */
      if (number_bytes <= 4)
        p=q+8;
      else
        {
          /*
            The directory entry contains an offset.
          */
          offset=(ssize_t) ReadProfileLong(endian,q+8);
          if ((ssize_t) (offset+number_bytes) < offset)
            continue;  /* prevent overflow */
          if ((size_t) (offset+number_bytes) > length)
            continue;
          p=(unsigned char *) (exif+offset);
        }
      switch (tag_value)
      {
        case 0x011a:
        {
          (void) WriteProfileLong(endian,(size_t) (image->x_resolution+0.5),p);
          (void) WriteProfileLong(endian,1UL,p+4);
          break;
        }
        case 0x011b:
        {
          (void) WriteProfileLong(endian,(size_t) (image->y_resolution+0.5),p);
          (void) WriteProfileLong(endian,1UL,p+4);
          break;
        }
        case 0x0112:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2083,10 +2083,10 @@
             The directory entry contains an offset.
           */
           offset=(ssize_t) ReadProfileLong(endian,q+8);
-          if ((ssize_t) (offset+number_bytes) < offset)
+          if ((offset < 0) || ((size_t) (offset+number_bytes) > length))
+            continue;
+          if (~length < number_bytes)
             continue;  /* prevent overflow */
-          if ((size_t) (offset+number_bytes) > length)
-            continue;
           p=(unsigned char *) (exif+offset);
         }
       switch (tag_value)
```
