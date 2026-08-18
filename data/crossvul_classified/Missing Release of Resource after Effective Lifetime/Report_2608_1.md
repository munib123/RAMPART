# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2608_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2608_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 7888-7928 of the vulnerable file.

  sax_modules.getParameterEntity=MSLGetParameterEntity;
  sax_modules.cdataBlock=MSLCDataBlock;
  sax_modules.externalSubset=MSLExternalSubset;
  sax_handler=(&sax_modules);
  msl_info.parser=xmlCreatePushParserCtxt(sax_handler,&msl_info,(char *) NULL,0,
    msl_image->filename);
  while (ReadBlobString(msl_image,message) != (char *) NULL)
  {
    n=(ssize_t) strlen(message);
    if (n == 0)
      continue;
    status=xmlParseChunk(msl_info.parser,message,(int) n,MagickFalse);
    if (status != 0)
      break;
    (void) xmlParseChunk(msl_info.parser," ",1,MagickFalse);
    if (msl_info.exception->severity >= ErrorException)
      break;
  }
  if (msl_info.exception->severity == UndefinedException)
    (void) xmlParseChunk(msl_info.parser," ",1,MagickTrue);
  xmlFreeParserCtxt(msl_info.parser);
  (void) LogMagickEvent(CoderEvent,GetMagickModule(),"end SAX");
  msl_info.group_info=(MSLGroupInfo *) RelinquishMagickMemory(
    msl_info.group_info);
  if (*image == (Image *) NULL)
    *image=(*msl_info.image);
  if (msl_info.exception->severity != UndefinedException)
    return(MagickFalse);
  return(MagickTrue);
}

static Image *ReadMSLImage(const ImageInfo *image_info,ExceptionInfo *exception)
{
  Image
    *image;

  /*
    Open image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickCoreSignature);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7905,12 +7905,25 @@
   }
   if (msl_info.exception->severity == UndefinedException)
     (void) xmlParseChunk(msl_info.parser," ",1,MagickTrue);
+  /*
+    Free resources.
+  */
   xmlFreeParserCtxt(msl_info.parser);
   (void) LogMagickEvent(CoderEvent,GetMagickModule(),"end SAX");
   msl_info.group_info=(MSLGroupInfo *) RelinquishMagickMemory(
     msl_info.group_info);
   if (*image == (Image *) NULL)
     *image=(*msl_info.image);
+  *msl_info.image_info=DestroyImageInfo(*msl_info.image_info);
+  msl_info.image_info=(ImageInfo **) RelinquishMagickMemory(
+    msl_info.image_info);
+  *msl_info.draw_info=DestroyDrawInfo(*msl_info.draw_info);
+  msl_info.draw_info=(DrawInfo **) RelinquishMagickMemory(msl_info.draw_info);
+  msl_info.image=(Image **) RelinquishMagickMemory(msl_info.image);
+  *msl_info.attributes=DestroyImage(*msl_info.attributes);
+  msl_info.attributes=(Image **) RelinquishMagickMemory(msl_info.attributes);
+  msl_info.group_info=(MSLGroupInfo *) RelinquishMagickMemory(
+    msl_info.group_info);
   if (msl_info.exception->severity != UndefinedException)
     return(MagickFalse);
   return(MagickTrue);
```
