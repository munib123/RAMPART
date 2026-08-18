# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1423_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1423_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

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
FILE_RCSID("@(#)$File: readelf.c,v 1.156 2018/10/19 00:33:04 christos Exp $")
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
-FILE_RCSID("@(#)$File: readelf.c,v 1.156 2018/10/19 00:33:04 christos Exp $")
+FILE_RCSID("@(#)$File: readelf.c,v 1.157 2019/01/02 19:44:14 christos Exp $")
 #endif
 
 #ifdef BUILTIN_ELF
@@ -752,7 +752,7 @@
 			char sbuf[512];
 			struct NetBSD_elfcore_procinfo pi;
 			memset(&pi, 0, sizeof(pi));
-			memcpy(&pi, nbuf + doff, descsz);
+			memcpy(&pi, nbuf + doff, MIN(descsz, sizeof(pi)));
 
 			if (file_printf(ms, ", from '%.31s', pid=%u, uid=%u, "
 			    "gid=%u, nlwps=%u, lwp=%u (signal %u/code %u)",
```
