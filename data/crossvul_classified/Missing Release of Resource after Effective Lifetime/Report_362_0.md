# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 362_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `362_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 3122-3162 of the vulnerable file.

    profile;

  PSDInfo
    info;

  StringInfo
    *layers;

  base_image=CloneImage(image,0,0,MagickFalse,exception);
  if (base_image == (Image *) NULL)
    return(MagickTrue);
  clone_info=CloneImageInfo(image_info);
  if (clone_info == (ImageInfo *) NULL)
    ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
      image->filename);
  profile.offset=0;
  profile.quantum=MagickMinBlobExtent;
  layers=AcquireStringInfo(profile.quantum);
  if (layers == (StringInfo *) NULL)
    {
      clone_info=DestroyImageInfo(clone_info);
      ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
        image->filename);
    }
  profile.data=layers;
  profile.extent=layers->length;
  custom_stream=TIFFAcquireCustomStreamForWriting(&profile,exception);
  if (custom_stream == (CustomStreamInfo *) NULL)
    {
      clone_info=DestroyImageInfo(clone_info);
      layers=DestroyStringInfo(layers);
      ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
        image->filename);
    }
  blob=CloneBlobInfo((BlobInfo *) NULL);
  if (blob == (BlobInfo *) NULL)
    {
      clone_info=DestroyImageInfo(clone_info);
      layers=DestroyStringInfo(layers);
      custom_stream=DestroyCustomStreamInfo(custom_stream);
      ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3139,6 +3139,7 @@
   layers=AcquireStringInfo(profile.quantum);
   if (layers == (StringInfo *) NULL)
     {
+      base_image=DestroyImage(base_image);
       clone_info=DestroyImageInfo(clone_info);
       ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
         image->filename);
@@ -3148,6 +3149,7 @@
   custom_stream=TIFFAcquireCustomStreamForWriting(&profile,exception);
   if (custom_stream == (CustomStreamInfo *) NULL)
     {
+      base_image=DestroyImage(base_image);
       clone_info=DestroyImageInfo(clone_info);
       layers=DestroyStringInfo(layers);
       ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
@@ -3156,6 +3158,7 @@
   blob=CloneBlobInfo((BlobInfo *) NULL);
   if (blob == (BlobInfo *) NULL)
     {
+      base_image=DestroyImage(base_image);
       clone_info=DestroyImageInfo(clone_info);
       layers=DestroyStringInfo(layers);
       custom_stream=DestroyCustomStreamInfo(custom_stream);
```
