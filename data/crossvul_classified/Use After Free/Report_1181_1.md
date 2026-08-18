# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1181_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1181_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 553-593 of the vulnerable file.

  image=error_manager->image;
  profile=BlobToStringInfo((const void *) NULL,length);
  if (profile == (StringInfo *) NULL)
    {
      (void) ThrowMagickException(exception,GetMagickModule(),
        ResourceLimitError,"MemoryAllocationFailed","`%s'",image->filename);
      return(FALSE);
    }
  error_manager->profile=profile;
  p=GetStringInfoDatum(profile);
  for (i=0; i < (ssize_t) length; i++)
  {
    int
      c;

    c=GetCharacter(jpeg_info);
    if (c == EOF)
      break;
    *p++=(unsigned char) c;
  }
  if (i != (ssize_t) length)
    {
      profile=DestroyStringInfo(profile);
      (void) ThrowMagickException(exception,GetMagickModule(),
        CorruptImageError,"InsufficientImageDataInFile","`%s'",
        image->filename);
      return(FALSE);
    }
  error_manager->profile=NULL;
  icc_profile=(StringInfo *) GetImageProfile(image,"icc");
  if (icc_profile != (StringInfo *) NULL)
    {
      ConcatenateStringInfo(icc_profile,profile);
      profile=DestroyStringInfo(profile);
    }
  else
    {
      status=SetImageProfile(image,"icc",profile,exception);
      profile=DestroyStringInfo(profile);
      if (status == MagickFalse)
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -570,6 +570,7 @@
       break;
     *p++=(unsigned char) c;
   }
+  error_manager->profile=NULL;
   if (i != (ssize_t) length)
     {
       profile=DestroyStringInfo(profile);
@@ -578,7 +579,6 @@
         image->filename);
       return(FALSE);
     }
-  error_manager->profile=NULL;
   icc_profile=(StringInfo *) GetImageProfile(image,"icc");
   if (icc_profile != (StringInfo *) NULL)
     {
@@ -704,7 +704,9 @@
         image->filename);
       return(FALSE);
     }
-  /* The IPTC profile is actually an 8bim */
+  /*
+    The IPTC profile is actually an 8bim.
+  */
   iptc_profile=(StringInfo *) GetImageProfile(image,"8bim");
   if (iptc_profile != (StringInfo *) NULL)
     {
```
