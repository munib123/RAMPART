# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2040_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2040_0`)

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
FILE_RCSID("@(#)$File: cdf.c,v 1.58 2014/05/13 16:41:06 christos Exp $")
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
-FILE_RCSID("@(#)$File: cdf.c,v 1.58 2014/05/13 16:41:06 christos Exp $")
+FILE_RCSID("@(#)$File: cdf.c,v 1.59 2014/05/14 23:22:48 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -827,6 +827,10 @@
 		    i, inp[i].pi_id, inp[i].pi_type, q - p, offs));
 		if (inp[i].pi_type & CDF_VECTOR) {
 			nelements = CDF_GETUINT32(q, 1);
+			if (nelements == 0) {
+				DPRINTF(("CDF_VECTOR with nelements == 0\n"));
+				goto out;
+			}
 			o = 2;
 		} else {
 			nelements = 1;
@@ -901,7 +905,9 @@
 			}
 			DPRINTF(("nelements = %" SIZE_T_FORMAT "u\n",
 			    nelements));
-			for (j = 0; j < nelements; j++, i++) {
+			for (j = 0; j < nelements && i < sh.sh_properties;
+			    j++, i++)
+			{
 				uint32_t l = CDF_GETUINT32(q, o);
 				inp[i].pi_str.s_len = l;
 				inp[i].pi_str.s_buf = (const char *)
```
