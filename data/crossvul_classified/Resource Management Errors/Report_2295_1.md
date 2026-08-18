# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2295_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2295_1`)

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

#ifndef lint
FILE_RCSID("@(#)$File: readelf.c,v 1.103 2014/05/02 02:25:10 christos Exp $")
#endif

#ifdef BUILTIN_ELF
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "readelf.h"
#include "magic.h"

#ifdef	ELFCORE
private int dophn_core(struct magic_set *, int, int, int, off_t, int, size_t,
    off_t, int *);
#endif
private int dophn_exec(struct magic_set *, int, int, int, off_t, int, size_t,
    off_t, int *, int);
private int doshn(struct magic_set *, int, int, int, off_t, int, size_t,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 #include "file.h"
 
 #ifndef lint
-FILE_RCSID("@(#)$File: readelf.c,v 1.103 2014/05/02 02:25:10 christos Exp $")
+FILE_RCSID("@(#)$File: readelf.c,v 1.104 2014/10/17 15:49:00 christos Exp $")
 #endif
 
 #ifdef BUILTIN_ELF
@@ -59,6 +59,18 @@
 private uint16_t getu16(int, uint16_t);
 private uint32_t getu32(int, uint32_t);
 private uint64_t getu64(int, uint64_t);
+
+#define MAX_PHNUM	256
+#define	MAX_SHNUM	1024
+
+private int
+toomany(struct magic_set *ms, const char *name, uint16_t num)
+{
+	if (file_printf(ms, ", too many %s header sections (%u)", name, num
+	    ) == -1)
+		return -1;
+	return 0;
+}
 
 private uint16_t
 getu16(int swap, uint16_t value)
@@ -499,13 +511,13 @@
 	if (namesz & 0x80000000) {
 	    (void)file_printf(ms, ", bad note name size 0x%lx",
 		(unsigned long)namesz);
-	    return offset;
+	    return 0;
 	}
 
 	if (descsz & 0x80000000) {
 	    (void)file_printf(ms, ", bad note description size 0x%lx",
 		(unsigned long)descsz);
-	    return offset;
+	    return 0;
 	}
 
 
@@ -1240,7 +1252,7 @@
 	int flags = 0;
 	Elf32_Ehdr elf32hdr;
 	Elf64_Ehdr elf64hdr;
-	uint16_t type;
+	uint16_t type, phnum, shnum;
 
 	if (ms->flags & (MAGIC_MIME|MAGIC_APPLE))
 		return 0;
```
