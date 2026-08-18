# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1196_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1196_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

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
FILE_RCSID("@(#)$File: cdf.c,v 1.115 2019/08/23 14:29:14 christos Exp $")
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
#include <limits.h>

#ifndef EFTYPE
#define EFTYPE EINVAL
#endif

#ifndef SIZE_T_MAX
#define SIZE_T_MAX CAST(size_t, ~0ULL)
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,7 +35,7 @@
 #include "file.h"
 
 #ifndef lint
-FILE_RCSID("@(#)$File: cdf.c,v 1.115 2019/08/23 14:29:14 christos Exp $")
+FILE_RCSID("@(#)$File: cdf.c,v 1.116 2019/08/26 14:31:39 christos Exp $")
 #endif
 
 #include <assert.h>
@@ -1027,8 +1027,9 @@
 				goto out;
 			}
 			nelements = CDF_GETUINT32(q, 1);
-			if (nelements == 0) {
-				DPRINTF(("CDF_VECTOR with nelements == 0\n"));
+			if (nelements > CDF_ELEMENT_LIMIT || nelements == 0) {
+				DPRINTF(("CDF_VECTOR with nelements == %"
+				    SIZE_T_FORMAT "u\n", nelements));
 				goto out;
 			}
 			slen = 2;
@@ -1070,8 +1071,6 @@
 					goto out;
 				inp += nelem;
 			}
-			DPRINTF(("nelements = %" SIZE_T_FORMAT "u\n",
-			    nelements));
 			for (j = 0; j < nelements && i < sh.sh_properties;
 			    j++, i++)
 			{
```
