# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2135_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2135_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

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
FILE_RCSID("@(#)$File: softmagic.c,v 1.189 2014/05/30 16:47:44 christos Exp $")
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
-FILE_RCSID("@(#)$File: softmagic.c,v 1.189 2014/05/30 16:47:44 christos Exp $")
+FILE_RCSID("@(#)$File: softmagic.c,v 1.190 2014/06/03 19:01:34 christos Exp $")
 #endif	/* lint */
 
 #include "magic.h"
@@ -940,10 +940,18 @@
 		return 1;
 	}
 	case FILE_PSTRING: {
-		char *ptr1 = p->s, *ptr2 = ptr1 + file_pstring_length_size(m);
+		size_t sz = file_pstring_length_size(m);
+		char *ptr1 = p->s, *ptr2 = ptr1 + sz;
 		size_t len = file_pstring_get_length(m, ptr1);
-		if (len >= sizeof(p->s))
-			len = sizeof(p->s) - 1;
+		if (len >= sizeof(p->s)) {
+			/*
+			 * The size of the pascal string length (sz)
+			 * is 1, 2, or 4. We need at least 1 byte for NUL
+			 * termination, but we've already truncated the
+			 * string by p->s, so we need to deduct sz.
+			 */ 
+			len = sizeof(p->s) - sz;
+		}
 		while (len--)
 			*ptr1++ = *ptr2++;
 		*ptr1 = '\0';
```
