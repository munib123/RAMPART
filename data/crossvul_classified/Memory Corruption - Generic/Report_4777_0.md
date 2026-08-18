# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4777_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4777_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1910-1950 of the vulnerable file.

    length,
    tag_length;

  StringInfo
    *custom_profile;

  /*
    Save image profile as a APP marker.
  */
  iptc=MagickFalse;
  custom_profile=AcquireStringInfo(65535L);
  ResetImageProfileIterator(image);
  for (name=GetNextImageProfile(image); name != (const char *) NULL; )
  {
    register unsigned char
      *p;

    profile=GetImageProfile(image,name);
    p=GetStringInfoDatum(custom_profile);
    if (LocaleCompare(name,"EXIF") == 0)
      for (i=0; i < (ssize_t) GetStringInfoLength(profile); i+=65533L)
      {
        length=MagickMin(GetStringInfoLength(profile)-i,65533L);
        jpeg_write_marker(jpeg_info,XML_MARKER,GetStringInfoDatum(profile)+i,
          (unsigned int) length);
      }
    if (LocaleCompare(name,"ICC") == 0)
      {
        register unsigned char
          *p;

        tag_length=strlen(ICC_PROFILE);
        p=GetStringInfoDatum(custom_profile);
        (void) CopyMagickMemory(p,ICC_PROFILE,tag_length);
        p[tag_length]='\0';
        for (i=0; i < (ssize_t) GetStringInfoLength(profile); i+=65519L)
        {
          length=MagickMin(GetStringInfoLength(profile)-i,65519L);
          p[12]=(unsigned char) ((i/65519L)+1);
          p[13]=(unsigned char) (GetStringInfoLength(profile)/65519L+1);
          (void) CopyMagickMemory(p+tag_length+3,GetStringInfoDatum(profile)+i,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1927,10 +1927,15 @@
     profile=GetImageProfile(image,name);
     p=GetStringInfoDatum(custom_profile);
     if (LocaleCompare(name,"EXIF") == 0)
-      for (i=0; i < (ssize_t) GetStringInfoLength(profile); i+=65533L)
       {
-        length=MagickMin(GetStringInfoLength(profile)-i,65533L);
-        jpeg_write_marker(jpeg_info,XML_MARKER,GetStringInfoDatum(profile)+i,
+        length=GetStringInfoLength(profile);
+        if (length > 65533L)
+          {
+            (void) ThrowMagickException(&image->exception,GetMagickModule(),
+              CoderWarning,"ExifProfileSizeExceedsLimit",image->filename);
+            length=65533L;
+          }
+        jpeg_write_marker(jpeg_info,XML_MARKER,GetStringInfoDatum(profile),
           (unsigned int) length);
       }
     if (LocaleCompare(name,"ICC") == 0)
```
