# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5818_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5818_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 14-49 of the vulnerable file.

 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libavutil/attributes.h"
#include "libavutil/common.h"
#include "png.h"
#include "pngdsp.h"

// 0x7f7f7f7f or 0x7f7f7f7f7f7f7f7f or whatever, depending on the cpu's native arithmetic size
#define pb_7f (~0UL/255 * 0x7f)
#define pb_80 (~0UL/255 * 0x80)

static void add_bytes_l2_c(uint8_t *dst, uint8_t *src1, uint8_t *src2, int w)
{
    long i;
    for (i = 0; i <= w - sizeof(long); i += sizeof(long)) {
        long a = *(long *)(src1 + i);
        long b = *(long *)(src2 + i);
        *(long *)(dst + i) = ((a & pb_7f) + (b & pb_7f)) ^ ((a ^ b) & pb_80);
    }
    for (; i < w; i++)
        dst[i] = src1[i] + src2[i];
}

av_cold void ff_pngdsp_init(PNGDSPContext *dsp)
{
    dsp->add_bytes_l2         = add_bytes_l2_c;
    dsp->add_paeth_prediction = ff_add_png_paeth_prediction;

    if (ARCH_X86) ff_pngdsp_init_x86(dsp);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,7 @@
 static void add_bytes_l2_c(uint8_t *dst, uint8_t *src1, uint8_t *src2, int w)
 {
     long i;
-    for (i = 0; i <= w - sizeof(long); i += sizeof(long)) {
+    for (i = 0; i <= w - (int)sizeof(long); i += sizeof(long)) {
         long a = *(long *)(src1 + i);
         long b = *(long *)(src2 + i);
         *(long *)(dst + i) = ((a & pb_7f) + (b & pb_7f)) ^ ((a ^ b) & pb_80);
```
