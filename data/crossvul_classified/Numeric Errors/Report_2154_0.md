# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2154_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2154_0`)

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
FILE_RCSID("@(#)$File: cdf.c,v 1.63 2014/06/09 13:04:37 christos Exp $")
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
-FILE_RCSID("@(#)$File: cdf.c,v 1.63 2014/06/09 13:04:37 christos Exp $")
+FILE_RCSID("@(#)$File: cdf.c,v 1.64 2014/07/24 19:35:39 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -835,6 +835,10 @@
 		q = (const uint8_t *)(const void *)
 		    ((const char *)(const void *)p + ofs
 		    - 2 * sizeof(uint32_t));
+		if (q < p) {
+			DPRINTF(("Wrapped around %p < %p\n", q, p));
+			goto out;
+		}
 		if (q > e) {
 			DPRINTF(("Ran of the end %p > %p\n", q, e));
 			goto out;
```
