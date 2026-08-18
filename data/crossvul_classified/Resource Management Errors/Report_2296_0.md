# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2296_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2296_0`)

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
FILE_RCSID("@(#)$File: readelf.c,v 1.104 2014/10/17 15:49:00 christos Exp $")
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
-FILE_RCSID("@(#)$File: readelf.c,v 1.104 2014/10/17 15:49:00 christos Exp $")
+FILE_RCSID("@(#)$File: readelf.c,v 1.105 2014/11/22 16:04:29 christos Exp $")
 #endif
 
 #ifdef BUILTIN_ELF
@@ -919,6 +919,7 @@
 	Elf32_Shdr sh32;
 	Elf64_Shdr sh64;
 	int stripped = 1;
+	size_t nbadcap = 0;
 	void *nbuf;
 	off_t noff, coff, name_off;
 	uint64_t cap_hw1 = 0;	/* SunOS 5.x hardware capabilites */
@@ -1007,6 +1008,8 @@
 				goto skip;
 			}
 
+			if (nbadcap > 5)
+				break;
 			if (lseek(fd, xsh_offset, SEEK_SET) == (off_t)-1) {
 				file_badseek(ms);
 				return -1;
@@ -1072,6 +1075,8 @@
 					    (unsigned long long)xcap_tag,
 					    (unsigned long long)xcap_val) == -1)
 						return -1;
+					if (nbadcap++ > 2)
+						coff = xsh_size;
 					break;
 				}
 			}
```
