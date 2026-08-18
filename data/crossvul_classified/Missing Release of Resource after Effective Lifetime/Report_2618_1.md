# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2618_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2618_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 3273-3314 of the vulnerable file.

    j,
    y;

  assert(image != (Image *) NULL);
  assert(image->signature == MagickSignature);
  if (image->type != GrayscaleType)
    (void) TransformImageColorspace(image,GRAYColorspace);
  colormap_index=(ssize_t *) AcquireQuantumMemory(MaxColormapSize,
    sizeof(*colormap_index));
  if (colormap_index == (ssize_t *) NULL)
    ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
      image->filename);
  if (image->storage_class != PseudoClass)
    {
      ExceptionInfo
        *exception;

      (void) ResetMagickMemory(colormap_index,(-1),MaxColormapSize*
        sizeof(*colormap_index));
      if (AcquireImageColormap(image,MaxColormapSize) == MagickFalse)
        ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
          image->filename);
      image->colors=0;
      status=MagickTrue;
      exception=(&image->exception);
      image_view=AcquireAuthenticCacheView(image,exception);
#if defined(MAGICKCORE_OPENMP_SUPPORT)
      #pragma omp parallel for schedule(static,4) shared(status) \
        magick_threads(image,image,image->rows,1)
#endif
      for (y=0; y < (ssize_t) image->rows; y++)
      {
        register IndexPacket
          *magick_restrict indexes;

        register PixelPacket
          *magick_restrict q;

        register ssize_t
          x;

        if (status == MagickFalse)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3290,8 +3290,11 @@
       (void) ResetMagickMemory(colormap_index,(-1),MaxColormapSize*
         sizeof(*colormap_index));
       if (AcquireImageColormap(image,MaxColormapSize) == MagickFalse)
-        ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
-          image->filename);
+        {
+          colormap_index=(ssize_t *) RelinquishMagickMemory(colormap_index);
+          ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
+            image->filename);
+        }
       image->colors=0;
       status=MagickTrue;
       exception=(&image->exception);
```
