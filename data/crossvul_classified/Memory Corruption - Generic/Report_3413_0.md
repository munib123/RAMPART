# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3413_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3413_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 12-52 of the vulnerable file.

 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libavutil/parseutils.h"
#include "libavutil/avstring.h"
#include "avcodec.h"
#include "internal.h"

typedef struct XPMContext {
    uint32_t  *pixels;
    int        pixels_size;
} XPMDecContext;

typedef struct ColorEntry {
    const char *name;         ///< a string representing the name of the color
    uint32_t    rgb_color;    ///< RGB values for the color
} ColorEntry;

static int color_table_compare(const void *lhs, const void *rhs)
{
    return av_strcasecmp(lhs, ((const ColorEntry *)rhs)->name);
}

static const ColorEntry color_table[] = {
    { "AliceBlue",            0xFFF0F8FF },
    { "AntiqueWhite",         0xFFFAEBD7 },
    { "Aqua",                 0xFF00FFFF },
    { "Aquamarine",           0xFF7FFFD4 },
    { "Azure",                0xFFF0FFFF },
    { "Beige",                0xFFF5F5DC },
    { "Bisque",               0xFFFFE4C4 },
    { "Black",                0xFF000000 },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,8 @@
 typedef struct XPMContext {
     uint32_t  *pixels;
     int        pixels_size;
+    uint8_t   *buf;
+    int        buf_size;
 } XPMDecContext;
 
 typedef struct ColorEntry {
@@ -233,6 +235,8 @@
     const ColorEntry *entry;
     char color_name[100];
 
+    len = FFMIN(FFMAX(len, 0), sizeof(color_name) - 1);
+
     if (*p == '#') {
         p++;
         len--;
@@ -299,18 +303,25 @@
 {
     XPMDecContext *x = avctx->priv_data;
     AVFrame *p=data;
-    const uint8_t *end, *ptr = avpkt->data;
+    const uint8_t *end, *ptr;
     int ncolors, cpp, ret, i, j;
     int64_t size;
     uint32_t *dst;
 
     avctx->pix_fmt = AV_PIX_FMT_BGRA;
 
-    end = avpkt->data + avpkt->size;
-    while (memcmp(ptr, "/* XPM */", 9) && ptr < end - 9)
+    av_fast_padded_malloc(&x->buf, &x->buf_size, avpkt->size);
+    if (!x->buf)
+        return AVERROR(ENOMEM);
+    memcpy(x->buf, avpkt->data, avpkt->size);
+    x->buf[avpkt->size] = 0;
+
+    ptr = x->buf;
+    end = x->buf + avpkt->size;
+    while (end - ptr > 9 && memcmp(ptr, "/* XPM */", 9))
         ptr++;
 
-    if (ptr >= end) {
+    if (end - ptr <= 9) {
         av_log(avctx, AV_LOG_ERROR, "missing signature\n");
         return AVERROR_INVALIDDATA;
     }
@@ -335,7 +346,7 @@
 
     size = 1;
     for (i = 0; i < cpp; i++)
-        size *= 94;
+        size *= 95;
 
     if (ncolors <= 0 || ncolors > size) {
         av_log(avctx, AV_LOG_ERROR, "invalid number of colors: %d\n", ncolors);
@@ -349,12 +360,15 @@
         return AVERROR(ENOMEM);
 
     ptr += mod_strcspn(ptr, ",") + 1;
+    if (end - ptr < 1)
+        return AVERROR_INVALIDDATA;
+
     for (i = 0; i < ncolors; i++) {
         const uint8_t *index;
         int len;
 
         ptr += mod_strcspn(ptr, "\"") + 1;
-        if (ptr + cpp > end)
+        if (end - ptr < cpp)
             return AVERROR_INVALIDDATA;
         index = ptr;
         ptr += cpp;
@@ -373,14 +387,20 @@
 
         x->pixels[ret] = color_string_to_rgba(ptr, len);
         ptr += mod_strcspn(ptr, ",") + 1;
+        if (end - ptr < 1)
+            return AVERROR_INVALIDDATA;
     }
 
     for (i = 0; i < avctx->height; i++) {
         dst = (uint32_t *)(p->data[0] + i * p->linesize[0]);
+        if (end - ptr < 1)
+            return AVERROR_INVALIDDATA;
         ptr += mod_strcspn(ptr, "\"") + 1;
+        if (end - ptr < 1)
+            return AVERROR_INVALIDDATA;
 
         for (j = 0; j < avctx->width; j++) {
-            if (ptr + cpp > end)
+            if (end - ptr < cpp)
                 return AVERROR_INVALIDDATA;
 
             if ((ret = ascii2index(ptr, cpp)) < 0)
@@ -404,6 +424,9 @@
 {
     XPMDecContext *x = avctx->priv_data;
     av_freep(&x->pixels);
+
+    av_freep(&x->buf);
+    x->buf_size = 0;
 
     return 0;
 }
```
