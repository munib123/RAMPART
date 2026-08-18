# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5312_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5312_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2596-2636 of the vulnerable file.

  unsigned char
    *datum;

  unsigned int
    count,
    long_sans;

  unsigned short
    id,
    short_sans;

  length=GetStringInfoLength(bim_profile);
  if (length < 16)
    return;
  datum=GetStringInfoDatum(bim_profile);
  for (p=datum; (p >= datum) && (p < (datum+length-16)); )
  {
    register unsigned char
      *q;

    q=(unsigned char *) p;
    if (LocaleNCompare((const char *) p,"8BIM",4) != 0)
      break;
    p=PushLongPixel(MSBEndian,p,&long_sans);
    p=PushShortPixel(MSBEndian,p,&id);
    p=PushShortPixel(MSBEndian,p,&short_sans);
    p=PushLongPixel(MSBEndian,p,&count);
    if ((id == 0x000003ed) && (PSDQuantum(count) < (ssize_t) (length-12)))
      {
        (void) CopyMagickMemory(q,q+PSDQuantum(count)+12,length-
          (PSDQuantum(count)+12)-(q-datum));
        SetStringInfoLength(bim_profile,length-(PSDQuantum(count)+12));
        break;
      }
    p+=count;
    if ((count & 0x01) != 0)
      p++;
  }
}

static MagickBooleanType WritePSDImage(const ImageInfo *image_info,Image *image,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2613,18 +2613,23 @@
     register unsigned char
       *q;
 
+    ssize_t
+      cnt;
+
     q=(unsigned char *) p;
     if (LocaleNCompare((const char *) p,"8BIM",4) != 0)
-      break;
+      return;
     p=PushLongPixel(MSBEndian,p,&long_sans);
     p=PushShortPixel(MSBEndian,p,&id);
     p=PushShortPixel(MSBEndian,p,&short_sans);
     p=PushLongPixel(MSBEndian,p,&count);
-    if ((id == 0x000003ed) && (PSDQuantum(count) < (ssize_t) (length-12)))
+    cnt=PSDQuantum(count);
+    if (cnt < 0)
+      return;
+    if ((id == 0x000003ed) && (cnt < (ssize_t) (length-12)))
       {
-        (void) CopyMagickMemory(q,q+PSDQuantum(count)+12,length-
-          (PSDQuantum(count)+12)-(q-datum));
-        SetStringInfoLength(bim_profile,length-(PSDQuantum(count)+12));
+        (void) CopyMagickMemory(q,q+cnt+12,length-(cnt+12)-(q-datum));
+        SetStringInfoLength(bim_profile,length-(cnt+12));
         break;
       }
     p+=count;
@@ -2633,8 +2638,8 @@
   }
 }
 
-static MagickBooleanType WritePSDImage(const ImageInfo *image_info,Image *image,
-  ExceptionInfo *exception)
+static MagickBooleanType WritePSDImage(const ImageInfo *image_info,
+  Image *image,ExceptionInfo *exception)
 {
   const char
     *property;
```
