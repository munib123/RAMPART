# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2297_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2297_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 15-55 of the vulnerable file.

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
/*
 * softmagic - interpret variable magic from MAGIC
 */

#include "file.h"

#ifndef	lint
FILE_RCSID("@(#)$File: softmagic.c,v 1.196 2014/11/07 15:24:14 christos Exp $")
#endif	/* lint */

#include "magic.h"
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

private int match(struct magic_set *, struct magic *, uint32_t,
    const unsigned char *, size_t, size_t, int, int, int, int, int *, int *,
    int *);
private int mget(struct magic_set *, const unsigned char *,
    struct magic *, size_t, size_t, unsigned int, int, int, int, int, int *,
    int *, int *);
private int magiccheck(struct magic_set *, struct magic *);
private int32_t mprint(struct magic_set *, struct magic *);
private int32_t moffset(struct magic_set *, struct magic *);
private void mdebug(uint32_t, const char *, size_t);
private int mcopy(struct magic_set *, union VALUETYPE *, int, int,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
 #include "file.h"
 
 #ifndef	lint
-FILE_RCSID("@(#)$File: softmagic.c,v 1.196 2014/11/07 15:24:14 christos Exp $")
+FILE_RCSID("@(#)$File: softmagic.c,v 1.197 2014/11/11 17:48:23 christos Exp $")
 #endif	/* lint */
 
 #include "magic.h"
@@ -63,6 +63,9 @@
 private void cvt_64(union VALUETYPE *, const struct magic *);
 
 #define OFFSET_OOB(n, o, i)	((n) < (o) || (i) > ((n) - (o)))
+
+#define MAX_RECURSION_LEVEL	10
+
 /*
  * softmagic - lookup one file in parsed, in-memory copy of database
  * Passed the name and FILE * of one file to be typed.
@@ -1217,14 +1220,15 @@
     int flip, int recursion_level, int *printed_something,
     int *need_separator, int *returnval)
 {
-	uint32_t soffset, offset = ms->offset;
+	uint32_t offset = ms->offset;
 	uint32_t lhs;
+	file_pushbuf_t *pb;
 	int rv, oneed_separator, in_type;
-	char *sbuf, *rbuf;
+	char *rbuf;
 	union VALUETYPE *p = &ms->ms_value;
 	struct mlist ml;
 
-	if (recursion_level >= 20) {
+	if (recursion_level >= MAX_RECURSION_LEVEL) {
 		file_error(ms, 0, "recursion nesting exceeded");
 		return -1;
 	}
@@ -1669,19 +1673,23 @@
 	case FILE_INDIRECT:
 		if (offset == 0)
 			return 0;
+
 		if (nbytes < offset)
 			return 0;
-		sbuf = ms->o.buf;
-		soffset = ms->offset;
-		ms->o.buf = NULL;
-		ms->offset = 0;
+
+		if ((pb = file_push_buffer(ms)) == NULL)
+			return -1;
+
 		rv = file_softmagic(ms, s + offset, nbytes - offset,
 		    recursion_level, BINTEST, text);
+
 		if ((ms->flags & MAGIC_DEBUG) != 0)
 			fprintf(stderr, "indirect @offs=%u[%d]\n", offset, rv);
-		rbuf = ms->o.buf;
-		ms->o.buf = sbuf;
-		ms->offset = soffset;
+
+		rbuf = file_pop_buffer(ms, pb);
+		if (rbuf == NULL)
+			return -1;
+
 		if (rv == 1) {
 			if ((ms->flags & (MAGIC_MIME|MAGIC_APPLE)) == 0 &&
 			    file_printf(ms, F(ms, m, "%u"), offset) == -1) {
@@ -1699,13 +1707,13 @@
 	case FILE_USE:
 		if (nbytes < offset)
 			return 0;
-		sbuf = m->value.s;
-		if (*sbuf == '^') {
-			sbuf++;
+		rbuf = m->value.s;
+		if (*rbuf == '^') {
+			rbuf++;
 			flip = !flip;
 		}
-		if (file_magicfind(ms, sbuf, &ml) == -1) {
-			file_error(ms, 0, "cannot find entry `%s'", sbuf);
+		if (file_magicfind(ms, rbuf, &ml) == -1) {
+			file_error(ms, 0, "cannot find entry `%s'", rbuf);
 			return -1;
 		}
 
```
