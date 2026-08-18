# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2137_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2137_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

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
FILE_RCSID("@(#)$File: cdf.c,v 1.59 2014/05/14 23:22:48 christos Exp $")
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
-FILE_RCSID("@(#)$File: cdf.c,v 1.59 2014/05/14 23:22:48 christos Exp $")
+FILE_RCSID("@(#)$File: cdf.c,v 1.60 2014/05/21 13:04:38 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -455,7 +455,8 @@
 cdf_count_chain(const cdf_sat_t *sat, cdf_secid_t sid, size_t size)
 {
 	size_t i, j;
-	cdf_secid_t maxsector = (cdf_secid_t)(sat->sat_len * size);
+	cdf_secid_t maxsector = (cdf_secid_t)((sat->sat_len * size)
+	    / sizeof(maxsector));
 
 	DPRINTF(("Chain:"));
 	for (j = i = 0; sid >= 0; i++, j++) {
@@ -465,8 +466,8 @@
 			errno = EFTYPE;
 			return (size_t)-1;
 		}
-		if (sid > maxsector) {
-			DPRINTF(("Sector %d > %d\n", sid, maxsector));
+		if (sid >= maxsector) {
+			DPRINTF(("Sector %d >= %d\n", sid, maxsector));
 			errno = EFTYPE;
 			return (size_t)-1;
 		}
```
