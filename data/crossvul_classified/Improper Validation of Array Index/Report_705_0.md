# CrossVul Fix Pair: Improper Validation of Array Index in c
**Pair ID:** 705_0
**Vulnerability Class:** Improper Validation of Array Index
**CWE:** CWE-129
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `705_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Array Index - The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position withi...

## Vulnerable Code
```c
Lines 12-54 of the vulnerable file.

 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libavutil/avassert.h"
#include "libavutil/pixfmt.h"

#include "cbs.h"
#include "cbs_internal.h"
#include "cbs_av1.h"
#include "internal.h"


static int cbs_av1_read_uvlc(CodedBitstreamContext *ctx, GetBitContext *gbc,
                             const char *name, uint32_t *write_to,
                             uint32_t range_min, uint32_t range_max)
{
    uint32_t value;
    int position, zeroes, i, j;
    char bits[65];

    if (ctx->trace_enable)
        position = get_bits_count(gbc);

    zeroes = i = 0;
    while (1) {
        if (get_bits_left(gbc) < zeroes + 1) {
            av_log(ctx->log_ctx, AV_LOG_ERROR, "Invalid uvlc code at "
                   "%s: bitstream ended.\n", name);
            return AVERROR_INVALIDDATA;
        }

        if (get_bits1(gbc)) {
            bits[i++] = '1';
            break;
        } else {
            bits[i++] = '0';
            ++zeroes;
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,45 +29,67 @@
                              const char *name, uint32_t *write_to,
                              uint32_t range_min, uint32_t range_max)
 {
-    uint32_t value;
-    int position, zeroes, i, j;
-    char bits[65];
+    uint32_t zeroes, bits_value, value;
+    int position;
 
     if (ctx->trace_enable)
         position = get_bits_count(gbc);
 
-    zeroes = i = 0;
+    zeroes = 0;
     while (1) {
-        if (get_bits_left(gbc) < zeroes + 1) {
+        if (get_bits_left(gbc) < 1) {
             av_log(ctx->log_ctx, AV_LOG_ERROR, "Invalid uvlc code at "
                    "%s: bitstream ended.\n", name);
             return AVERROR_INVALIDDATA;
         }
 
-        if (get_bits1(gbc)) {
-            bits[i++] = '1';
+        if (get_bits1(gbc))
             break;
-        } else {
-            bits[i++] = '0';
-            ++zeroes;
-        }
+        ++zeroes;
     }
 
     if (zeroes >= 32) {
         value = MAX_UINT_BITS(32);
     } else {
-        value = get_bits_long(gbc, zeroes);
-
-        for (j = 0; j < zeroes; j++)
-            bits[i++] = (value >> (zeroes - j - 1) & 1) ? '1' : '0';
-
-        value += (1 << zeroes) - 1;
+        if (get_bits_left(gbc) < zeroes) {
+            av_log(ctx->log_ctx, AV_LOG_ERROR, "Invalid uvlc code at "
+                   "%s: bitstream ended.\n", name);
+            return AVERROR_INVALIDDATA;
+        }
+
+        bits_value = get_bits_long(gbc, zeroes);
+        value = bits_value + (UINT32_C(1) << zeroes) - 1;
     }
 
     if (ctx->trace_enable) {
+        char bits[65];
+        int i, j, k;
+
+        if (zeroes >= 32) {
+            while (zeroes > 32) {
+                k = FFMIN(zeroes - 32, 32);
+                for (i = 0; i < k; i++)
+                    bits[i] = '0';
+                bits[i] = 0;
+                ff_cbs_trace_syntax_element(ctx, position, name,
+                                            NULL, bits, 0);
+                zeroes -= k;
+                position += k;
+            }
+        }
+
+        for (i = 0; i < zeroes; i++)
+            bits[i] = '0';
+        bits[i++] = '1';
+
+        if (zeroes < 32) {
+            for (j = 0; j < zeroes; j++)
+                bits[i++] = (bits_value >> (zeroes - j - 1) & 1) ? '1' : '0';
+        }
+
         bits[i] = 0;
-        ff_cbs_trace_syntax_element(ctx, position, name, NULL,
-                                    bits, value);
+        ff_cbs_trace_syntax_element(ctx, position, name,
+                                    NULL, bits, value);
     }
 
     if (value < range_min || value > range_max) {
```
