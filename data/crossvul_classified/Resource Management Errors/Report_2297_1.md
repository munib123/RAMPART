# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2297_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2297_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 10-50 of the vulnerable file.

 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "file.h"

#ifndef	lint
FILE_RCSID("@(#)$File: funcs.c,v 1.72 2014/05/14 23:15:42 christos Exp $")
#endif	/* lint */

#include "magic.h"
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#if defined(HAVE_WCHAR_H)
#include <wchar.h>
#endif
#if defined(HAVE_WCTYPE_H)
#include <wctype.h>
#endif
#if defined(HAVE_LIMITS_H)
#include <limits.h>
#endif

#ifndef SIZE_MAX
#define SIZE_MAX	((size_t)~0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 #include "file.h"
 
 #ifndef	lint
-FILE_RCSID("@(#)$File: funcs.c,v 1.72 2014/05/14 23:15:42 christos Exp $")
+FILE_RCSID("@(#)$File: funcs.c,v 1.73 2014/09/10 18:41:51 christos Exp $")
 #endif	/* lint */
 
 #include "magic.h"
@@ -491,3 +491,43 @@
 	file_magerror(ms, "regex error %d for `%s', (%s)", rc, rx->pat,
 	    errmsg);
 }
+
+protected file_pushbuf_t *
+file_push_buffer(struct magic_set *ms)
+{
+	file_pushbuf_t *pb;
+
+	if (ms->event_flags & EVENT_HAD_ERR)
+		return NULL;
+
+	if ((pb = (CAST(file_pushbuf_t *, malloc(sizeof(*pb))))) == NULL)
+		return NULL;
+
+	pb->buf = ms->o.buf;
+	pb->offset = ms->offset;
+
+	ms->o.buf = NULL;
+	ms->offset = 0;
+
+	return pb;
+}
+
+protected char *
+file_pop_buffer(struct magic_set *ms, file_pushbuf_t *pb)
+{
+	char *rbuf;
+
+	if (ms->event_flags & EVENT_HAD_ERR) {
+		free(pb->buf);
+		free(pb);
+		return NULL;
+	}
+
+	rbuf = ms->o.buf;
+
+	ms->o.buf = pb->buf;
+	ms->offset = pb->offset;
+
+	free(pb);
+	return rbuf;
+}
```
