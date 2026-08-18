# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5485_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5485_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 620-661 of the vulnerable file.

    }
  if ((TIFFGetField(tiff,37724,&length,&profile) == 1) &&
      (profile != (unsigned char *) NULL))
    (void) ReadProfile(image,"tiff:37724",profile,(ssize_t) length,exception);
}

static void TIFFGetProperties(TIFF *tiff,Image *image,ExceptionInfo *exception)
{
  char
    message[MagickPathExtent],
    *text;

  uint32
    count,
    length,
    type;

  unsigned long
    *tietz;


  if (TIFFGetField(tiff,TIFFTAG_ARTIST,&text) == 1)
    (void) SetImageProperty(image,"tiff:artist",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_COPYRIGHT,&text) == 1)
    (void) SetImageProperty(image,"tiff:copyright",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_DATETIME,&text) == 1)
    (void) SetImageProperty(image,"tiff:timestamp",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_DOCUMENTNAME,&text) == 1)
    (void) SetImageProperty(image,"tiff:document",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_HOSTCOMPUTER,&text) == 1)
    (void) SetImageProperty(image,"tiff:hostcomputer",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_IMAGEDESCRIPTION,&text) == 1)
    (void) SetImageProperty(image,"comment",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_MAKE,&text) == 1)
    (void) SetImageProperty(image,"tiff:make",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_MODEL,&text) == 1)
    (void) SetImageProperty(image,"tiff:model",text,exception);
  if (TIFFGetField(tiff,TIFFTAG_OPIIMAGEID,&count,&text) == 1)
    {
      if (count >= MagickPathExtent)
        count=MagickPathExtent-1;
      (void) CopyMagickString(message,text,count+1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -637,42 +637,54 @@
   unsigned long
     *tietz;
 
-
-  if (TIFFGetField(tiff,TIFFTAG_ARTIST,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_ARTIST,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"tiff:artist",text,exception);
-  if (TIFFGetField(tiff,TIFFTAG_COPYRIGHT,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_COPYRIGHT,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"tiff:copyright",text,exception);
-  if (TIFFGetField(tiff,TIFFTAG_DATETIME,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_DATETIME,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"tiff:timestamp",text,exception);
-  if (TIFFGetField(tiff,TIFFTAG_DOCUMENTNAME,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_DOCUMENTNAME,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"tiff:document",text,exception);
-  if (TIFFGetField(tiff,TIFFTAG_HOSTCOMPUTER,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_HOSTCOMPUTER,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"tiff:hostcomputer",text,exception);
-  if (TIFFGetField(tiff,TIFFTAG_IMAGEDESCRIPTION,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_IMAGEDESCRIPTION,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"comment",text,exception);
-  if (TIFFGetField(tiff,TIFFTAG_MAKE,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_MAKE,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"tiff:make",text,exception);
-  if (TIFFGetField(tiff,TIFFTAG_MODEL,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_MODEL,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"tiff:model",text,exception);
-  if (TIFFGetField(tiff,TIFFTAG_OPIIMAGEID,&count,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_OPIIMAGEID,&count,&text) == 1) &&
+      (text != (char *) NULL))
     {
       if (count >= MagickPathExtent)
         count=MagickPathExtent-1;
       (void) CopyMagickString(message,text,count+1);
       (void) SetImageProperty(image,"tiff:image-id",message,exception);
     }
-  if (TIFFGetField(tiff,TIFFTAG_PAGENAME,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_PAGENAME,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"label",text,exception);
-  if (TIFFGetField(tiff,TIFFTAG_SOFTWARE,&text) == 1)
+  if ((TIFFGetField(tiff,TIFFTAG_SOFTWARE,&text) == 1) &&
+      (text != (char *) NULL))
     (void) SetImageProperty(image,"tiff:software",text,exception);
-  if (TIFFGetField(tiff,33423,&count,&text) == 1)
+  if ((TIFFGetField(tiff,33423,&count,&text) == 1) &&
+      (text != (char *) NULL))
     {
       if (count >= MagickPathExtent)
         count=MagickPathExtent-1;
       (void) CopyMagickString(message,text,count+1);
       (void) SetImageProperty(image,"tiff:kodak-33423",message,exception);
     }
-  if (TIFFGetField(tiff,36867,&count,&text) == 1)
+  if ((TIFFGetField(tiff,36867,&count,&text) == 1) &&
+      (text != (char *) NULL))
     {
       if (count >= MagickPathExtent)
         count=MagickPathExtent-1;
@@ -701,7 +713,8 @@
       default:
         break;
     }
-  if (TIFFGetField(tiff,37706,&length,&tietz) == 1)
+  if ((TIFFGetField(tiff,37706,&length,&tietz) == 1) &&
+      (tietz != (unsigned long *) NULL))
     {
       (void) FormatLocaleString(message,MagickPathExtent,"%lu",tietz[0]);
       (void) SetImageProperty(image,"tiff:tietz_offset",message,exception);
```
