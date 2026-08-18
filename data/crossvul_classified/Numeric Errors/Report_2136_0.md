# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2136_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2136_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

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
FILE_RCSID("@(#)$File: cdf.c,v 1.60 2014/05/21 13:04:38 christos Exp $")
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
-FILE_RCSID("@(#)$File: cdf.c,v 1.60 2014/05/21 13:04:38 christos Exp $")
+FILE_RCSID("@(#)$File: cdf.c,v 1.61 2014/06/04 17:23:19 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -267,13 +267,15 @@
 {
 	const char *b = (const char *)sst->sst_tab;
 	const char *e = ((const char *)p) + tail;
+	size_t ss = sst->sst_dirlen < h->h_min_size_standard_stream ?
+	    CDF_SHORT_SEC_SIZE(h) : CDF_SEC_SIZE(h);
 	(void)&line;
-	if (e >= b && (size_t)(e - b) <= CDF_SEC_SIZE(h) * sst->sst_len)
+	if (e >= b && (size_t)(e - b) <= ss * sst->sst_len)
 		return 0;
 	DPRINTF(("%d: offset begin %p < end %p || %" SIZE_T_FORMAT "u"
 	    " > %" SIZE_T_FORMAT "u [%" SIZE_T_FORMAT "u %"
 	    SIZE_T_FORMAT "u]\n", line, b, e, (size_t)(e - b),
-	    CDF_SEC_SIZE(h) * sst->sst_len, CDF_SEC_SIZE(h), sst->sst_len));
+	    ss * sst->sst_len, ss, sst->sst_len));
 	errno = EFTYPE;
 	return -1;
 }
```
