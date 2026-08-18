# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2392_5
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2392_5`)

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
 * file - find type of a file or files - main program.
 */

#include "file.h"

#ifndef	lint
FILE_RCSID("@(#)$File: file.c,v 1.158 2014/11/28 02:35:05 christos Exp $")
#endif	/* lint */

#include "magic.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef RESTORE_TIME
# if (__COHERENT__ >= 0x420)
#  include <sys/utime.h>
# else
#  ifdef USE_UTIMES
#   include <sys/time.h>
#  else
#   include <utime.h>
#  endif
# endif
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* for read() */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
 #include "file.h"
 
 #ifndef	lint
-FILE_RCSID("@(#)$File: file.c,v 1.158 2014/11/28 02:35:05 christos Exp $")
+FILE_RCSID("@(#)$File: file.c,v 1.159 2014/11/28 02:46:39 christos Exp $")
 #endif	/* lint */
 
 #include "magic.h"
@@ -125,6 +125,7 @@
 	{ "name",	MAGIC_PARAM_NAME_MAX, 0 },
 	{ "elf_phnum",	MAGIC_PARAM_ELF_PHNUM_MAX, 0 },
 	{ "elf_shnum",	MAGIC_PARAM_ELF_SHNUM_MAX, 0 },
+	{ "elf_notes",	MAGIC_PARAM_ELF_NOTES_MAX, 0 },
 };
 
 private char *progname;		/* used throughout 		*/
```
