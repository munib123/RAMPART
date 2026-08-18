# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 927_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `927_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 94-134 of the vulnerable file.


static inline PixelTrait GetPixelBlueTraits(const Image *magick_restrict image)
{
  return(image->channel_map[BluePixelChannel].traits);
}

static inline Quantum GetPixelCb(const Image *magick_restrict image,
  const Quantum *magick_restrict pixel)
{
  return(pixel[image->channel_map[CbPixelChannel].offset]);
}

static inline PixelTrait GetPixelCbTraits(const Image *magick_restrict image)
{
  return(image->channel_map[CbPixelChannel].traits);
}

static inline Quantum GetPixelChannel(const Image *magick_restrict image,
  const PixelChannel channel,const Quantum *magick_restrict pixel)
{
  if (image->channel_map[image->channel_map[channel].offset].traits == UndefinedPixelTrait)
    return((Quantum) 0);
  return(pixel[image->channel_map[channel].offset]);
}

static inline PixelChannel GetPixelChannelChannel(
  const Image *magick_restrict image,const ssize_t offset)
{
  return(image->channel_map[offset].channel);
}

static inline ssize_t GetPixelChannelOffset(const Image *magick_restrict image,
  const PixelChannel channel)
{
  return(image->channel_map[channel].offset);
}

static inline PixelTrait GetPixelChannelTraits(
  const Image *magick_restrict image,const PixelChannel channel)
{
  return(image->channel_map[channel].traits);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,7 +111,7 @@
 static inline Quantum GetPixelChannel(const Image *magick_restrict image,
   const PixelChannel channel,const Quantum *magick_restrict pixel)
 {
-  if (image->channel_map[image->channel_map[channel].offset].traits == UndefinedPixelTrait)
+  if (image->channel_map[channel].traits == UndefinedPixelTrait)
     return((Quantum) 0);
   return(pixel[image->channel_map[channel].offset]);
 }
```
