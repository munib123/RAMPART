# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2401_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2401_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

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
FILE_RCSID("@(#)$File: readelf.c,v 1.113 2014/12/11 14:10:53 christos Exp $")
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
-FILE_RCSID("@(#)$File: readelf.c,v 1.113 2014/12/11 14:10:53 christos Exp $")
+FILE_RCSID("@(#)$File: readelf.c,v 1.114 2014/12/11 14:19:36 christos Exp $")
 #endif
 
 #ifdef BUILTIN_ELF
@@ -319,7 +319,7 @@
 	 * Loop through all the program headers.
 	 */
 	for ( ; num; num--) {
-		if (pread(fd, xph_addr, xph_sizeof, off) == -1) {
+		if (pread(fd, xph_addr, xph_sizeof, off) < (ssize_t)xph_sizeof) {
 			file_badread(ms);
 			return -1;
 		}
@@ -928,6 +928,7 @@
 	uint64_t cap_hw1 = 0;	/* SunOS 5.x hardware capabilites */
 	uint64_t cap_sf1 = 0;	/* SunOS 5.x software capabilites */
 	char name[50];
+	ssize_t namesize;
 
 	if (size != xsh_sizeof) {
 		if (file_printf(ms, ", corrupted section header size") == -1)
@@ -936,7 +937,7 @@
 	}
 
 	/* Read offset of name section to be able to read section names later */
-	if (pread(fd, xsh_addr, xsh_sizeof, off + size * strtab) == -1) {
+	if (pread(fd, xsh_addr, xsh_sizeof, off + size * strtab) < (ssize_t)xsh_sizeof) {
 		file_badread(ms);
 		return -1;
 	}
@@ -944,15 +945,15 @@
 
 	for ( ; num; num--) {
 		/* Read the name of this section. */
-		if (pread(fd, name, sizeof(name), name_off + xsh_name) == -1) {
+		if ((namesize = pread(fd, name, sizeof(name) - 1, name_off + xsh_name)) == -1) {
 			file_badread(ms);
 			return -1;
 		}
-		name[sizeof(name) - 1] = '\0';
+		name[namesize] = '\0';
 		if (strcmp(name, ".debug_info") == 0)
 			stripped = 0;
 
-		if (pread(fd, xsh_addr, xsh_sizeof, off) == -1) {
+		if (pread(fd, xsh_addr, xsh_sizeof, off) < (ssize_t)xsh_sizeof) {
 			file_badread(ms);
 			return -1;
 		}
@@ -982,7 +983,7 @@
 				    " for note");
 				return -1;
 			}
-			if (pread(fd, nbuf, xsh_size, xsh_offset) == -1) {
+			if (pread(fd, nbuf, xsh_size, xsh_offset) < (ssize_t)xsh_size) {
 				file_badread(ms);
 				free(nbuf);
 				return -1;
@@ -1178,7 +1179,7 @@
 	}
 
   	for ( ; num; num--) {
-		if (pread(fd, xph_addr, xph_sizeof, off) == -1) {
+		if (pread(fd, xph_addr, xph_sizeof, off) < (ssize_t)xph_sizeof) {
 			file_badread(ms);
 			return -1;
 		}
```
