# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2147_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2147_0`)

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
FILE_RCSID("@(#)$File: softmagic.c,v 1.187 2014/05/13 16:42:17 christos Exp $")
#endif	/* lint */

#include "magic.h"
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#if defined(HAVE_LOCALE_H)
#include <locale.h>
#endif


private int match(struct magic_set *, struct magic *, uint32_t,
    const unsigned char *, size_t, size_t, int, int, int, int, int *, int *,
    int *);
private int mget(struct magic_set *, const unsigned char *,
    struct magic *, size_t, size_t, unsigned int, int, int, int, int, int *,
    int *, int *);
private int magiccheck(struct magic_set *, struct magic *);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
 #include "file.h"
 
 #ifndef	lint
-FILE_RCSID("@(#)$File: softmagic.c,v 1.187 2014/05/13 16:42:17 christos Exp $")
+FILE_RCSID("@(#)$File: softmagic.c,v 1.188 2014/05/14 23:15:42 christos Exp $")
 #endif	/* lint */
 
 #include "magic.h"
@@ -1929,15 +1929,23 @@
 			file_regerror(&rx, rc, ms);
 			v = (uint64_t)-1;
 		} else {
+#ifndef REG_STARTEND
+			char c;
+#endif
 			regmatch_t pmatch[1];
+			size_t slen = ms->search.s_len;
+			/* Limit by offset if requested */
+			if (m->str_range > 0)
+				slen = MIN(slen, m->str_range);
 #ifndef REG_STARTEND
 #define	REG_STARTEND	0
-			size_t l = ms->search.s_len - 1;
-			char c = ms->search.s[l];
-			((char *)(intptr_t)ms->search.s)[l] = '\0';
+			if (slen != 0)
+				slen--;
+			c = ms->search.s[slen];
+			((char *)(intptr_t)ms->search.s)[slen] = '\0';
 #else
 			pmatch[0].rm_so = 0;
-			pmatch[0].rm_eo = ms->search.s_len;
+			pmatch[0].rm_eo = slen;
 #endif
 			rc = file_regexec(&rx, (const char *)ms->search.s,
 			    1, pmatch, REG_STARTEND);
```
