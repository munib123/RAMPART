# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2138_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2138_0`)

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
FILE_RCSID("@(#)$File: cdf.c,v 1.61 2014/06/04 17:23:19 christos Exp $")
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
-FILE_RCSID("@(#)$File: cdf.c,v 1.61 2014/06/04 17:23:19 christos Exp $")
+FILE_RCSID("@(#)$File: cdf.c,v 1.62 2014/06/04 17:26:07 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -816,7 +816,11 @@
 	if (cdf_check_stream_offset(sst, h, e, 0, __LINE__) == -1)
 		goto out;
 	for (i = 0; i < sh.sh_properties; i++) {
-		size_t ofs = CDF_GETUINT32(p, (i << 1) + 1);
+		size_t tail = (i << 1) + 1;
+		if (cdf_check_stream_offset(sst, h, p, tail * sizeof(uint32_t),
+		    __LINE__) == -1)
+			goto out;
+		size_t ofs = CDF_GETUINT32(p, tail);
 		q = (const uint8_t *)(const void *)
 		    ((const char *)(const void *)p + ofs
 		    - 2 * sizeof(uint32_t));
```
