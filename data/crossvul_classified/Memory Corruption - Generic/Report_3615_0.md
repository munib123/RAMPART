# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3615_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3615_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 18-58 of the vulnerable file.

 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Parse Composite Document Files, the format used in Microsoft Office
 * document files before they switched to zipped XML.
 * Info from: http://sc.openoffice.org/compdocfileformat.pdf
 *
 * N.B. This is the "Composite Document File" format, and not the
 * "Compound Document Format", nor the "Channel Definition Format".
 */

#include "file.h"

#ifndef lint
FILE_RCSID("@(#)$File: cdf.c,v 1.45 2011/08/28 08:38:48 christos Exp $")
#endif

#include <assert.h>
#ifdef CDF_DEBUG
#include <err.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifndef EFTYPE
#define EFTYPE EINVAL
#endif

#include "cdf.h"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,7 +35,7 @@
 #include "file.h"
 
 #ifndef lint
-FILE_RCSID("@(#)$File: cdf.c,v 1.45 2011/08/28 08:38:48 christos Exp $")
+FILE_RCSID("@(#)$File: cdf.c,v 1.46 2011/09/16 21:23:59 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -341,18 +341,25 @@
 cdf_read_sector(const cdf_info_t *info, void *buf, size_t offs, size_t len,
     const cdf_header_t *h, cdf_secid_t id)
 {
-	assert((size_t)CDF_SEC_SIZE(h) == len);
-	return cdf_read(info, (off_t)CDF_SEC_POS(h, id),
-	    ((char *)buf) + offs, len);
+	size_t ss = CDF_SEC_SIZE(h);
+	size_t pos = CDF_SEC_POS(h, id);
+	assert(ss == len);
+	return cdf_read(info, (off_t)pos, ((char *)buf) + offs, len);
 }
 
 ssize_t
 cdf_read_short_sector(const cdf_stream_t *sst, void *buf, size_t offs,
     size_t len, const cdf_header_t *h, cdf_secid_t id)
 {
-	assert((size_t)CDF_SHORT_SEC_SIZE(h) == len);
+	size_t ss = CDF_SHORT_SEC_SIZE(h);
+	size_t pos = CDF_SHORT_SEC_POS(h, id);
+	assert(ss == len);
+	if (sst->sst_len < (size_t)id) {
+		DPRINTF(("bad sector id %d > %d\n", id, sst->sst_len));
+		return -1;
+	}
 	(void)memcpy(((char *)buf) + offs,
-	    ((const char *)sst->sst_tab) + CDF_SHORT_SEC_POS(h, id), len);
+	    ((const char *)sst->sst_tab) + pos, len);
 	return len;
 }
 
@@ -868,6 +875,8 @@
 				    inp[i].pi_str.s_buf));
 				l = 4 + (uint32_t)CDF_ROUND(l, sizeof(l));
 				o += l >> 2;
+				if (q + o >= e)
+					goto out;
 				o4 = o * sizeof(uint32_t);
 			}
 			i--;
```
