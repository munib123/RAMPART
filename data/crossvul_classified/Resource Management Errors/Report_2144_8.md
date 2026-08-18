# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2144_8
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2144_8`)

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
 * apprentice - make one pass through /etc/magic, learning its secrets.
 */

#include "file.h"

#ifndef	lint
FILE_RCSID("@(#)$File: apprentice.c,v 1.209 2014/05/13 16:42:17 christos Exp $")
#endif	/* lint */

#include "magic.h"
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#ifdef QUICK
#include <sys/mman.h>
#endif
#include <dirent.h>
#if defined(HAVE_LIMITS_H)
#include <limits.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
 #include "file.h"
 
 #ifndef	lint
-FILE_RCSID("@(#)$File: apprentice.c,v 1.209 2014/05/13 16:42:17 christos Exp $")
+FILE_RCSID("@(#)$File: apprentice.c,v 1.210 2014/05/14 23:15:42 christos Exp $")
 #endif	/* lint */
 
 #include "magic.h"
@@ -1382,7 +1382,8 @@
 	if ((ms->flags & MAGIC_CHECK) == 0)
 		return 0;
 
-	if (m->type != FILE_PSTRING && (m->str_flags & PSTRING_LEN) != 0) {
+	if ((m->type != FILE_REGEX || (m->str_flags & REGEX_LINE_COUNT) == 0) &&
+	    (m->type != FILE_PSTRING && (m->str_flags & PSTRING_LEN) != 0)) {
 		file_magwarn(ms,
 		    "'/BHhLl' modifiers are only allowed for pascal strings\n");
 		return -1;
@@ -1875,8 +1876,13 @@
 					m->str_flags = (m->str_flags & ~PSTRING_LEN) | PSTRING_4_BE;
 					break;
 				case CHAR_PSTRING_4_LE:
-					if (m->type != FILE_PSTRING)
+					switch (m->type) {
+					case FILE_PSTRING:
+					case FILE_REGEX:
+						break;
+					default:
 						goto bad;
+					}
 					m->str_flags = (m->str_flags & ~PSTRING_LEN) | PSTRING_4_LE;
 					break;
 				case CHAR_PSTRING_LENGTH_INCLUDES_ITSELF:
```
