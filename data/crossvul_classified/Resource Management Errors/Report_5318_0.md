# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5318_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5318_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 3407-3459 of the vulnerable file.

%  OpenPixelCache() allocates the pixel cache.  This includes defining the cache
%  dimensions, allocating space for the image pixels and optionally the
%  colormap indexes, and memory mapping the cache if it is disk based.  The
%  cache nexus array is initialized as well.
%
%  The format of the OpenPixelCache() method is:
%
%      MagickBooleanType OpenPixelCache(Image *image,const MapMode mode,
%        ExceptionInfo *exception)
%
%  A description of each parameter follows:
%
%    o image: the image.
%
%    o mode: ReadMode, WriteMode, or IOMode.
%
%    o exception: return any errors or warnings in this structure.
%
*/

static inline void AllocatePixelCachePixels(CacheInfo *cache_info)
{
  cache_info->mapped=MagickFalse;
  cache_info->pixels=(PixelPacket *) MagickAssumeAligned(
    AcquireAlignedMemory(1,(size_t) cache_info->length));
  if (cache_info->pixels == (PixelPacket *) NULL)
    {
      cache_info->mapped=MagickTrue;
      cache_info->pixels=(PixelPacket *) MapBlob(-1,IOMode,0,(size_t)
        cache_info->length);
    }
}

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#if defined(SIGBUS)
static void CacheSignalHandler(int status)
{
  ThrowFatalException(CacheFatalError,"UnableToExtendPixelCache");
}
#endif

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

static MagickBooleanType OpenPixelCacheOnDisk(CacheInfo *cache_info,
  const MapMode mode)
{
  int
    file;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3424,19 +3424,6 @@
 %
 */
 
-static inline void AllocatePixelCachePixels(CacheInfo *cache_info)
-{
-  cache_info->mapped=MagickFalse;
-  cache_info->pixels=(PixelPacket *) MagickAssumeAligned(
-    AcquireAlignedMemory(1,(size_t) cache_info->length));
-  if (cache_info->pixels == (PixelPacket *) NULL)
-    {
-      cache_info->mapped=MagickTrue;
-      cache_info->pixels=(PixelPacket *) MapBlob(-1,IOMode,0,(size_t)
-        cache_info->length);
-    }
-}
-
 #if defined(__cplusplus) || defined(c_plusplus)
 extern "C" {
 #endif
@@ -3656,7 +3643,9 @@
       if (((cache_info->type == UndefinedCache) && (status != MagickFalse)) ||
           (cache_info->type == MemoryCache))
         {
-          AllocatePixelCachePixels(cache_info);
+          cache_info->mapped=MagickFalse;
+          cache_info->pixels=(PixelPacket *) MagickAssumeAligned(
+            AcquireAlignedMemory(1,(size_t) cache_info->length));
           if (cache_info->pixels == (PixelPacket *) NULL)
             cache_info->pixels=source_info.pixels;
           else
```
