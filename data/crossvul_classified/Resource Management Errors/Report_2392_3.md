# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2392_3
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2392_3`)

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
FILE_RCSID("@(#)$File: apprentice.c,v 1.226 2014/11/28 02:35:05 christos Exp $")
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
-FILE_RCSID("@(#)$File: apprentice.c,v 1.226 2014/11/28 02:35:05 christos Exp $")
+FILE_RCSID("@(#)$File: apprentice.c,v 1.227 2014/11/28 02:46:39 christos Exp $")
 #endif	/* lint */
 
 #include "magic.h"
@@ -528,6 +528,7 @@
 	ms->name_max = FILE_NAME_MAX;
 	ms->elf_shnum_max = FILE_ELF_SHNUM_MAX;
 	ms->elf_phnum_max = FILE_ELF_PHNUM_MAX;
+	ms->elf_notes_max = FILE_ELF_NOTES_MAX;
 	return ms;
 free:
 	free(ms);
```
