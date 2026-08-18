# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5292_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5292_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 580-639 of the vulnerable file.

%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% %
%  ClonePixelCacheRepository() clones the source pixel cache to the destination
%  cache.
%
%  The format of the ClonePixelCacheRepository() method is:
%
%      MagickBooleanType ClonePixelCacheRepository(CacheInfo *cache_info,
%        CacheInfo *source_info,ExceptionInfo *exception)
%
%  A description of each parameter follows:
%
%    o cache_info: the pixel cache.
%
%    o source_info: the source pixel cache.
%
%    o exception: return any errors or warnings in this structure.
%
*/

static inline void CopyPixels(PixelPacket *destination,
  const PixelPacket *source,const MagickSizeType number_pixels)
{
#if !defined(MAGICKCORE_OPENMP_SUPPORT) || (MAGICKCORE_QUANTUM_DEPTH <= 8)
  (void) memcpy(destination,source,(size_t) number_pixels*sizeof(*source));
#else
  {
    register MagickOffsetType
      i;

    if ((number_pixels*sizeof(*source)) < MagickMaxBufferExtent)
      {
        (void) memcpy(destination,source,(size_t) number_pixels*
          sizeof(*source));
        return;
      }
    #pragma omp parallel for
    for (i=0; i < (MagickOffsetType) number_pixels; i++)
      destination[i]=source[i];
  }
#endif
}

static inline MagickSizeType MagickMin(const MagickSizeType x,
  const MagickSizeType y)
{
  if (x < y)
    return(x);
  return(y);
}

static MagickBooleanType ClonePixelCacheRepository(
  CacheInfo *restrict clone_info,CacheInfo *restrict cache_info,
  ExceptionInfo *exception)
{
#define MaxCacheThreads  2
#define cache_threads(source,destination,chunk) \
  num_threads((chunk) < (16*GetMagickResourceLimit(ThreadResource)) ? 1 : \
    GetMagickResourceLimit(ThreadResource) < MaxCacheThreads ? \
    GetMagickResourceLimit(ThreadResource) : MaxCacheThreads)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -597,29 +597,6 @@
 %
 */
 
-static inline void CopyPixels(PixelPacket *destination,
-  const PixelPacket *source,const MagickSizeType number_pixels)
-{
-#if !defined(MAGICKCORE_OPENMP_SUPPORT) || (MAGICKCORE_QUANTUM_DEPTH <= 8)
-  (void) memcpy(destination,source,(size_t) number_pixels*sizeof(*source));
-#else
-  {
-    register MagickOffsetType
-      i;
-
-    if ((number_pixels*sizeof(*source)) < MagickMaxBufferExtent)
-      {
-        (void) memcpy(destination,source,(size_t) number_pixels*
-          sizeof(*source));
-        return;
-      }
-    #pragma omp parallel for
-    for (i=0; i < (MagickOffsetType) number_pixels; i++)
-      destination[i]=source[i];
-  }
-#endif
-}
-
 static inline MagickSizeType MagickMin(const MagickSizeType x,
   const MagickSizeType y)
 {
@@ -665,8 +642,8 @@
       /*
         Identical pixel cache morphology.
       */
-      CopyPixels(clone_info->pixels,cache_info->pixels,cache_info->columns*
-        cache_info->rows);
+      (void) memcpy(clone_info->pixels,cache_info->pixels,cache_info->columns*
+        cache_info->rows*sizeof(*cache_info->pixels));
       if ((cache_info->active_index_channel != MagickFalse) &&
           (clone_info->active_index_channel != MagickFalse))
         (void) memcpy(clone_info->indexes,cache_info->indexes,
```
