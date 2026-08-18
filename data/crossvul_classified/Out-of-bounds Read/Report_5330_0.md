# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5330_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5330_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2028-2068 of the vulnerable file.

    {
      int
        components;

      register unsigned char
        *p,
        *q;

      size_t
        number_bytes;

      ssize_t
        format,
        tag_value;

      q=(unsigned char *) (directory+2+(12*entry));
      if (q > (exif+length-12))
        break;  /* corrupt EXIF */
      tag_value=(ssize_t) ReadProfileShort(endian,q);
      format=(ssize_t) ReadProfileShort(endian,q+2);
      if ((format-1) >= EXIF_NUM_FORMATS)
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
          offset=(ssize_t)  ReadProfileLong(endian,q+8);
          if ((size_t) (offset+number_bytes) > length)
            continue;
          if (~length < number_bytes)
            continue;  /* prevent overflow */
          p=(unsigned char *) (exif+offset);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2045,7 +2045,7 @@
         break;  /* corrupt EXIF */
       tag_value=(ssize_t) ReadProfileShort(endian,q);
       format=(ssize_t) ReadProfileShort(endian,q+2);
-      if ((format-1) >= EXIF_NUM_FORMATS)
+      if ((format < 0) || ((format-1) >= EXIF_NUM_FORMATS))
         break;
       components=(ssize_t) ReadProfileLong(endian,q+4);
       if (components < 0)
```
