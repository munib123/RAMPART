# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3616_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3616_0`)

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
FILE_RCSID("@(#)$File: cdf.c,v 1.48 2012/02/17 05:27:45 christos Exp $")
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
-FILE_RCSID("@(#)$File: cdf.c,v 1.48 2012/02/17 05:27:45 christos Exp $")
+FILE_RCSID("@(#)$File: cdf.c,v 1.49 2012/02/20 20:04:37 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -74,6 +74,7 @@
 #define CDF_TOLE4(x)	((uint32_t)(NEED_SWAP ? _cdf_tole4(x) : (uint32_t)(x)))
 #define CDF_TOLE2(x)	((uint16_t)(NEED_SWAP ? _cdf_tole2(x) : (uint16_t)(x)))
 #define CDF_GETUINT32(x, y)	cdf_getuint32(x, y)
+
 
 /*
  * swap a short
@@ -351,13 +352,13 @@
 cdf_read_short_sector(const cdf_stream_t *sst, void *buf, size_t offs,
     size_t len, const cdf_header_t *h, cdf_secid_t id)
 {
-	size_t ss = CDF_SEC_SIZE(h);
+	size_t ss = CDF_SHORT_SEC_SIZE(h);
 	size_t pos = CDF_SHORT_SEC_POS(h, id);
 	assert(ss == len);
-	if (pos > ss * sst->sst_len) {
+	if (pos > CDF_SEC_SIZE(h) * sst->sst_len) {
 		DPRINTF(("Out of bounds read %" SIZE_T_FORMAT "u > %"
 		    SIZE_T_FORMAT "u\n",
-		    pos, ss * sst->sst_len));
+		    pos, CDF_SEC_SIZE(h) * sst->sst_len));
 		return -1;
 	}
 	(void)memcpy(((char *)buf) + offs,
@@ -529,7 +530,7 @@
     const cdf_sat_t *ssat, const cdf_stream_t *sst,
     cdf_secid_t sid, size_t len, cdf_stream_t *scn)
 {
-	size_t ss = CDF_SEC_SIZE(h), i, j;
+	size_t ss = CDF_SHORT_SEC_SIZE(h), i, j;
 	scn->sst_len = cdf_count_chain(ssat, sid, CDF_SEC_SIZE(h));
 	scn->sst_dirlen = len;
 
@@ -798,18 +799,18 @@
 	if (cdf_check_stream_offset(sst, h, e, 0, __LINE__) == -1)
 		goto out;
 	for (i = 0; i < sh.sh_properties; i++) {
+		size_t ofs = CDF_GETUINT32(p, (i << 1) + 1);
 		q = (const uint8_t *)(const void *)
-		    ((const char *)(const void *)p +
-		    CDF_GETUINT32(p, (i << 1) + 1)) - 2 * sizeof(uint32_t);
+		    ((const char *)(const void *)p + ofs
+		    - 2 * sizeof(uint32_t));
 		if (q > e) {
 			DPRINTF(("Ran of the end %p > %p\n", q, e));
 			goto out;
 		}
 		inp[i].pi_id = CDF_GETUINT32(p, i << 1);
 		inp[i].pi_type = CDF_GETUINT32(q, 0);
-		DPRINTF(("%" SIZE_T_FORMAT "u) id=%x type=%x offs=0x%tx,0x%x\n", i,
-		    inp[i].pi_id, inp[i].pi_type, q - p,
-		    CDF_GETUINT32(p, (i << 1) + 1)));
+		DPRINTF(("%" SIZE_T_FORMAT "u) id=%x type=%x offs=0x%tx,0x%x\n",
+		    i, inp[i].pi_id, inp[i].pi_type, q - p, offs));
 		if (inp[i].pi_type & CDF_VECTOR) {
 			nelements = CDF_GETUINT32(q, 1);
 			o = 2;
```
