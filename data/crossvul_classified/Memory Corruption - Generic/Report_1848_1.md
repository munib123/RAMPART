# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1848_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1848_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

  See the License for the specific language governing permissions and
  limitations under the License.

  MagickCore pixel accessor methods.
*/
#ifndef _MAGICKCORE_PIXEL_ACCESSOR_H
#define _MAGICKCORE_PIXEL_ACCESSOR_H

#include "MagickCore/cache.h"
#include "MagickCore/cache-view.h"
#include "MagickCore/color.h"
#include "MagickCore/colorspace.h"
#include "MagickCore/gem.h"
#include "MagickCore/image.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#undef index

static inline Quantum GetPixela(const Image *restrict image,
  const Quantum *restrict pixel)
{
  return(pixel[image->channel_map[aPixelChannel].offset]);
}

static inline Quantum GetPixelAlpha(const Image *restrict image,
  const Quantum *restrict pixel)
{
  if (image->channel_map[AlphaPixelChannel].traits == UndefinedPixelTrait)
    return(OpaqueAlpha);
  return(pixel[image->channel_map[AlphaPixelChannel].offset]);
}

static inline PixelTrait GetPixelAlphaTraits(const Image *restrict image)
{
  return(image->channel_map[AlphaPixelChannel].traits);
}

static inline Quantum GetPixelb(const Image *restrict image,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,19 @@
 #endif
 
 #undef index
+
+static inline Quantum ClampPixel(const MagickRealType value)
+{
+#if !defined(MAGICKCORE_HDRI_SUPPORT)
+  return((Quantum) value);
+#else
+  if (value < 0.0)
+    return((Quantum) 0.0);
+  if (value >= (MagickRealType) QuantumRange)
+    return((Quantum) QuantumRange);
+  return((Quantum) value);
+#endif
+}
 
 static inline Quantum GetPixela(const Image *restrict image,
   const Quantum *restrict pixel)
```
