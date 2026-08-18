# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 3362_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3362_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 1657-1697 of the vulnerable file.

    Open image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickSignature);
  image=AcquireImage(image_info);
  status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
  if (status == MagickFalse)
    {
      image=DestroyImageList(image);
      return((Image *) NULL);
    }

  /*
    Initialize image structure.
  */
  if (ReadDDSInfo(image, &dds_info) != MagickTrue) {
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  }

  if (dds_info.ddscaps2 & DDSCAPS2_CUBEMAP)
    cubemap = MagickTrue;

  if (dds_info.ddscaps2 & DDSCAPS2_VOLUME && dds_info.depth > 0)
    volume = MagickTrue;

  (void) SeekBlob(image, 128, SEEK_SET);

  /*
    Determine pixel format
  */
  if (dds_info.pixelformat.flags & DDPF_RGB)
    {
      compression = NoCompression;
      if (dds_info.pixelformat.flags & DDPF_ALPHAPIXELS)
        {
          matte = MagickTrue;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1674,9 +1674,8 @@
   /*
     Initialize image structure.
   */
-  if (ReadDDSInfo(image, &dds_info) != MagickTrue) {
+  if (ReadDDSInfo(image, &dds_info) != MagickTrue)
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
-  }
 
   if (dds_info.ddscaps2 & DDSCAPS2_CUBEMAP)
     cubemap = MagickTrue;
@@ -1772,6 +1771,9 @@
 
   if (volume)
     num_images = dds_info.depth;
+
+  if (num_images < 1)
+    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
 
   for (n = 0; n < num_images; n++)
   {
```
