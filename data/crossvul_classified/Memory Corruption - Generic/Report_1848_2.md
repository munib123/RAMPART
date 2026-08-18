# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1848_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1848_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 676-728 of the vulnerable file.

%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  ClampImage() set each pixel whose value is below zero to zero and any the
%  pixel whose value is above the quantum range to the quantum range (e.g.
%  65535) otherwise the pixel value remains unchanged.
%
%  The format of the ClampImage method is:
%
%      MagickBooleanType ClampImage(Image *image,ExceptionInfo *exception)
%
%  A description of each parameter follows:
%
%    o image: the image.
%
%    o exception: return any errors or warnings in this structure.
%
*/

static inline Quantum ClampPixel(const MagickRealType value)
{
#if !defined(MAGICKCORE_HDRI_SUPPORT)
  return((Quantum) value);
#else
  if (value < 0.0f)
    return(0.0);
  if (value >= (MagickRealType) QuantumRange)
    return((Quantum) QuantumRange);
  return(value);
#endif
}

MagickExport MagickBooleanType ClampImage(Image *image,ExceptionInfo *exception)
{
#define ClampImageTag  "Clamp/Image"

  CacheView
    *image_view;

  MagickBooleanType
    status;

  MagickOffsetType
    progress;

  ssize_t
    y;

  assert(image != (Image *) NULL);
  assert(image->signature == MagickSignature);
  if (image->debug != MagickFalse)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -694,19 +694,6 @@
 %
 */
 
-static inline Quantum ClampPixel(const MagickRealType value)
-{
-#if !defined(MAGICKCORE_HDRI_SUPPORT)
-  return((Quantum) value);
-#else
-  if (value < 0.0f)
-    return(0.0);
-  if (value >= (MagickRealType) QuantumRange)
-    return((Quantum) QuantumRange);
-  return(value);
-#endif
-}
-
 MagickExport MagickBooleanType ClampImage(Image *image,ExceptionInfo *exception)
 {
 #define ClampImageTag  "Clamp/Image"
```
