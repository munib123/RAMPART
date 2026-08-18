# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5358_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5358_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 16-56 of the vulnerable file.

 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Libav; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "avformat.h"
#include "rawdec.h"

#define VISUAL_OBJECT_START_CODE       0x000001b5
#define VOP_START_CODE                 0x000001b6

static int mpeg4video_probe(AVProbeData *probe_packet)
{
    uint32_t temp_buffer = -1;
    int VO = 0, VOL = 0, VOP = 0, VISO = 0, res = 0;
    int i;

    for (i = 0; i < probe_packet->buf_size; i++) {
        temp_buffer = (temp_buffer << 8) + probe_packet->buf[i];
        if ((temp_buffer & 0xffffff00) != 0x100)
            continue;

        if (temp_buffer == VOP_START_CODE)
            VOP++;
        else if (temp_buffer == VISUAL_OBJECT_START_CODE)
            VISO++;
        else if (temp_buffer < 0x120)
            VO++;
        else if (temp_buffer < 0x130)
            VOL++;
        else if (!(0x1AF < temp_buffer && temp_buffer < 0x1B7) &&
                 !(0x1B9 < temp_buffer && temp_buffer < 0x1C4))
            res++;
    }

    if (VOP >= VISO && VOP >= VOL && VO >= VOL && VOL > 0 && res == 0)
        return AVPROBE_SCORE_EXTENSION;
    return 0;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,16 +33,18 @@
 
     for (i = 0; i < probe_packet->buf_size; i++) {
         temp_buffer = (temp_buffer << 8) + probe_packet->buf[i];
-        if ((temp_buffer & 0xffffff00) != 0x100)
+        if (temp_buffer & 0xfffffe00)
+            continue;
+        if (temp_buffer < 2)
             continue;
 
         if (temp_buffer == VOP_START_CODE)
             VOP++;
         else if (temp_buffer == VISUAL_OBJECT_START_CODE)
             VISO++;
-        else if (temp_buffer < 0x120)
+        else if (temp_buffer >= 0x100 && temp_buffer < 0x120)
             VO++;
-        else if (temp_buffer < 0x130)
+        else if (temp_buffer >= 0x120 && temp_buffer < 0x130)
             VOL++;
         else if (!(0x1AF < temp_buffer && temp_buffer < 0x1B7) &&
                  !(0x1B9 < temp_buffer && temp_buffer < 0x1C4))
```
