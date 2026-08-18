# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2039_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2039_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

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
FILE_RCSID("@(#)$File: cdf.c,v 1.55 2014/02/27 23:26:17 christos Exp $")
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
-FILE_RCSID("@(#)$File: cdf.c,v 1.55 2014/02/27 23:26:17 christos Exp $")
+FILE_RCSID("@(#)$File: cdf.c,v 1.56 2014/05/05 16:11:21 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -932,7 +932,7 @@
 cdf_unpack_summary_info(const cdf_stream_t *sst, const cdf_header_t *h,
     cdf_summary_info_header_t *ssi, cdf_property_info_t **info, size_t *count)
 {
-	size_t i, maxcount;
+	size_t maxcount;
 	const cdf_summary_info_header_t *si =
 	    CAST(const cdf_summary_info_header_t *, sst->sst_tab);
 	const cdf_section_declaration_t *sd =
@@ -947,21 +947,13 @@
 	ssi->si_os = CDF_TOLE2(si->si_os);
 	ssi->si_class = si->si_class;
 	cdf_swap_class(&ssi->si_class);
-	ssi->si_count = CDF_TOLE2(si->si_count);
+	ssi->si_count = CDF_TOLE4(si->si_count);
 	*count = 0;
 	maxcount = 0;
 	*info = NULL;
-	for (i = 0; i < CDF_TOLE4(si->si_count); i++) {
-		if (i >= CDF_LOOP_LIMIT) {
-			DPRINTF(("Unpack summary info loop limit"));
-			errno = EFTYPE;
-			return -1;
-		}
-		if (cdf_read_property_info(sst, h, CDF_TOLE4(sd->sd_offset),
-		    info, count, &maxcount) == -1) {
-			return -1;
-		}
-	}
+	if (cdf_read_property_info(sst, h, CDF_TOLE4(sd->sd_offset), info,
+	    count, &maxcount) == -1)
+		return -1;
 	return 0;
 }
 
```
