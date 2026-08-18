# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2637_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2637_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 29-69 of the vulnerable file.

%  distributed under the License is distributed on an "AS IS" BASIS,          %
%  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   %
%  See the License for the specific language governing permissions and        %
%  limitations under the License.                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%
%
*/


/*
  Include declarations.
*/
#include "MagickCore/studio.h"
#include "MagickCore/accelerate-private.h"
#include "MagickCore/artifact.h"
#include "MagickCore/attribute.h"
#include "MagickCore/cache.h"
#include "MagickCore/cache-view.h"
#include "MagickCore/channel.h"
#include "MagickCore/color.h"
#include "MagickCore/color-private.h"
#include "MagickCore/colorspace.h"
#include "MagickCore/colorspace-private.h"
#include "MagickCore/composite-private.h"
#include "MagickCore/enhance.h"
#include "MagickCore/exception.h"
#include "MagickCore/exception-private.h"
#include "MagickCore/fx.h"
#include "MagickCore/gem.h"
#include "MagickCore/gem-private.h"
#include "MagickCore/geometry.h"
#include "MagickCore/histogram.h"
#include "MagickCore/image.h"
#include "MagickCore/image-private.h"
#include "MagickCore/memory_.h"
#include "MagickCore/monitor.h"
#include "MagickCore/monitor-private.h"
#include "MagickCore/option.h"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,6 +46,7 @@
 #include "MagickCore/artifact.h"
 #include "MagickCore/attribute.h"
 #include "MagickCore/cache.h"
+#include "MagickCore/cache-private.h"
 #include "MagickCore/cache-view.h"
 #include "MagickCore/channel.h"
 #include "MagickCore/color.h"
@@ -1055,6 +1056,8 @@
   assert(image->signature == MagickCoreSignature);
   if (image->debug != MagickFalse)
     (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
+  if (SyncImagePixelCache(image,exception) == MagickFalse)
+    return(MagickFalse);
   if (SetImageGray(image,exception) != MagickFalse)
     (void) SetImageColorspace(image,GRAYColorspace,exception);
   black=(double *) AcquireQuantumMemory(GetPixelChannels(image),sizeof(*black));
@@ -1540,6 +1543,8 @@
   */
   assert(image != (Image *) NULL);
   assert(image->signature == MagickCoreSignature);
+  if (SyncImagePixelCache(image,exception) == MagickFalse)
+    return(MagickFalse);
 #if defined(MAGICKCORE_OPENCL_SUPPORT)
   if (AccelerateEqualizeImage(image,exception) != MagickFalse)
     return(MagickTrue);
```
