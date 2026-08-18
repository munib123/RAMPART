# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4484_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4484_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 11-51 of the vulnerable file.

 * License as published by the Free Software Foundation; either
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

/**
 * @file
 * @brief Vividas VIV (.viv) file demuxer
 * @author Andrzej Szombierski [qq at kuku eu org] (2010-07)
 * @sa http://wiki.multimedia.cx/index.php?title=Vividas_VIV
 */

#include "libavutil/intreadwrite.h"
#include "avio_internal.h"
#include "avformat.h"
#include "internal.h"

#define MAX_AUDIO_SUBPACKETS 100

typedef struct VIV_SB_block {
    int size, n_packets;
    int64_t byte_offset;
    int64_t packet_offset;
} VIV_SB_block;

typedef struct VIV_SB_entry {
    int size, flag;
} VIV_SB_entry;

typedef struct VIV_AudioSubpacket {
    int start, pcm_bytes;
} VIV_AudioSubpacket;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,7 @@
  * @sa http://wiki.multimedia.cx/index.php?title=Vividas_VIV
  */
 
+#include "libavutil/avassert.h"
 #include "libavutil/intreadwrite.h"
 #include "avio_internal.h"
 #include "avformat.h"
@@ -379,7 +380,7 @@
 
         if (avio_tell(pb) < off) {
             int num_data;
-            int xd_size = 0;
+            int xd_size = 1;
             int data_len[256];
             int offset = 1;
             uint8_t *p;
@@ -393,10 +394,10 @@
                     return AVERROR_INVALIDDATA;
                 }
                 data_len[j] = len;
-                xd_size += len;
+                xd_size += len + 1 + len/255;
             }
 
-            ret = ff_alloc_extradata(st->codecpar, 64 + xd_size + xd_size / 255);
+            ret = ff_alloc_extradata(st->codecpar, xd_size);
             if (ret < 0)
                 return ret;
 
@@ -405,9 +406,7 @@
 
             for (j = 0; j < num_data - 1; j++) {
                 unsigned delta = av_xiphlacing(&p[offset], data_len[j]);
-                if (delta > data_len[j]) {
-                    return AVERROR_INVALIDDATA;
-                }
+                av_assert0(delta <= xd_size - offset);
                 offset += delta;
             }
 
@@ -418,6 +417,7 @@
                     av_freep(&st->codecpar->extradata);
                     break;
                 }
+                av_assert0(data_len[j] <= xd_size - offset);
                 offset += data_len[j];
             }
 
```
