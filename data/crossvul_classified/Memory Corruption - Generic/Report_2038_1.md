# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2038_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2038_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 9-49 of the vulnerable file.

 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "file.h"

#ifndef lint
FILE_RCSID("@(#)$File: readcdf.c,v 1.39 2014/02/27 23:26:18 christos Exp $")
#endif

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#if defined(HAVE_LOCALE_H)
#include <locale.h>
#endif

#include "cdf.h"
#include "magic.h"

#define NOTMIME(ms) (((ms)->flags & MAGIC_MIME) == 0)

static const struct nv {
	const char *pattern;
	const char *mime;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
 #include "file.h"
 
 #ifndef lint
-FILE_RCSID("@(#)$File: readcdf.c,v 1.39 2014/02/27 23:26:18 christos Exp $")
+FILE_RCSID("@(#)$File: readcdf.c,v 1.40 2014/03/06 15:23:33 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -120,7 +120,7 @@
 
 private int
 cdf_file_property_info(struct magic_set *ms, const cdf_property_info_t *info,
-    size_t count, const uint64_t clsid[2])
+    size_t count, const cdf_directory_t *root_storage)
 {
         size_t i;
         cdf_timestamp_t tp;
@@ -130,8 +130,8 @@
         const char *s;
         int len;
 
-        if (!NOTMIME(ms))
-		str = cdf_clsid_to_mime(clsid, clsid2mime);
+        if (!NOTMIME(ms) && root_storage)
+		str = cdf_clsid_to_mime(root_storage->d_storage_uuid, clsid2mime);
 
         for (i = 0; i < count; i++) {
                 cdf_print_property_name(buf, sizeof(buf), info[i].pi_id);
@@ -236,7 +236,7 @@
 
 private int
 cdf_file_summary_info(struct magic_set *ms, const cdf_header_t *h,
-    const cdf_stream_t *sst, const uint64_t clsid[2])
+    const cdf_stream_t *sst, const cdf_directory_t *root_storage)
 {
         cdf_summary_info_header_t si;
         cdf_property_info_t *info;
@@ -276,13 +276,15 @@
                                 return -2;
                         break;
                 }
-		str = cdf_clsid_to_mime(clsid, clsid2desc);
-		if (str)
-                        if (file_printf(ms, ", %s", str) == -1)
-				return -2;
-        }
-
-        m = cdf_file_property_info(ms, info, count, clsid);
+		if (root_storage) {
+			str = cdf_clsid_to_mime(root_storage->d_storage_uuid, clsid2desc);
+			if (str)
+				if (file_printf(ms, ", %s", str) == -1)
+					return -2;
+			}
+		}
+
+        m = cdf_file_property_info(ms, info, count, root_storage);
         free(info);
 
         return m == -1 ? -2 : m;
@@ -381,9 +383,8 @@
 #ifdef CDF_DEBUG
         cdf_dump_summary_info(&h, &scn);
 #endif
-        if ((i = cdf_file_summary_info(ms, &h, &scn,
-	    root_storage->d_storage_uuid)) < 0)
-                expn = "Can't expand summary_info";
+        if ((i = cdf_file_summary_info(ms, &h, &scn, root_storage)) < 0)
+            expn = "Can't expand summary_info";
 
 	if (i == 0) {
 		const char *str = NULL;
```
