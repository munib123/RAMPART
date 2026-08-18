# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2393_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2393_0`)

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
FILE_RCSID("@(#)$File: readelf.c,v 1.115 2014/12/16 20:53:05 christos Exp $")
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
    off_t, int *, uint16_t *);
#endif
private int dophn_exec(struct magic_set *, int, int, int, off_t, int, size_t,
    off_t, int, int *, uint16_t *);
private int doshn(struct magic_set *, int, int, int, off_t, int, size_t,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 #include "file.h"
 
 #ifndef lint
-FILE_RCSID("@(#)$File: readelf.c,v 1.115 2014/12/16 20:53:05 christos Exp $")
+FILE_RCSID("@(#)$File: readelf.c,v 1.116 2014/12/16 23:18:40 christos Exp $")
 #endif
 
 #ifdef BUILTIN_ELF
@@ -900,19 +900,23 @@
 	}
 
 	if (namesz == 7 && strcmp((char *)&nbuf[noff], "NetBSD") == 0) {
+		if (descsz > 100)
+			descsz = 100;
 		switch (xnh_type) {
 	    	case NT_NETBSD_VERSION:
 			return size;
 		case NT_NETBSD_MARCH:
 			if (*flags & FLAGS_DID_NETBSD_MARCH)
 				return size;
-			if (file_printf(ms, ", compiled for: %.*s", (int)descsz,
-			    (const char *)&nbuf[doff]) == -1)
+			*flags |= FLAGS_DID_NETBSD_MARCH;
+			if (file_printf(ms, ", compiled for: %.*s",
+			    (int)descsz, (const char *)&nbuf[doff]) == -1)
 				return size;
 			break;
 		case NT_NETBSD_CMODEL:
 			if (*flags & FLAGS_DID_NETBSD_CMODEL)
 				return size;
+			*flags |= FLAGS_DID_NETBSD_CMODEL;
 			if (file_printf(ms, ", compiler model: %.*s",
 			    (int)descsz, (const char *)&nbuf[doff]) == -1)
 				return size;
@@ -920,6 +924,7 @@
 		default:
 			if (*flags & FLAGS_DID_NETBSD_UNKNOWN)
 				return size;
+			*flags |= FLAGS_DID_NETBSD_UNKNOWN;
 			if (file_printf(ms, ", note=%u", xnh_type) == -1)
 				return size;
 			break;
```
