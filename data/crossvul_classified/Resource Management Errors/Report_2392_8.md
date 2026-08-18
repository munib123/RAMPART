# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2392_8
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2392_8`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 16-56 of the vulnerable file.

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

#ifdef WIN32
#include <windows.h>
#include <shlwapi.h>
#endif

#include "file.h"

#ifndef	lint
FILE_RCSID("@(#)$File: magic.c,v 1.89 2014/11/28 02:46:39 christos Exp $")
#endif	/* lint */

#include "magic.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef QUICK
#include <sys/mman.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>	/* for PIPE_BUF */
#endif

#if defined(HAVE_UTIMES)
# include <sys/time.h>
#elif defined(HAVE_UTIME)
# if defined(HAVE_SYS_UTIME_H)
#  include <sys/utime.h>
# elif defined(HAVE_UTIME_H)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,7 +33,7 @@
 #include "file.h"
 
 #ifndef	lint
-FILE_RCSID("@(#)$File: magic.c,v 1.89 2014/11/28 02:46:39 christos Exp $")
+FILE_RCSID("@(#)$File: magic.c,v 1.90 2014/12/04 15:56:46 christos Exp $")
 #endif	/* lint */
 
 #include "magic.h"
@@ -554,6 +554,9 @@
 	case MAGIC_PARAM_ELF_SHNUM_MAX:
 		ms->elf_shnum_max = *(const size_t *)val;
 		return 0;
+	case MAGIC_PARAM_ELF_NOTES_MAX:
+		ms->elf_notes_max = *(const size_t *)val;
+		return 0;
 	default:
 		errno = EINVAL;
 		return -1;
@@ -576,6 +579,9 @@
 	case MAGIC_PARAM_ELF_SHNUM_MAX:
 		*(size_t *)val = ms->elf_shnum_max;
 		return 0;
+	case MAGIC_PARAM_ELF_NOTES_MAX:
+		*(size_t *)val = ms->elf_notes_max;
+		return 0;
 	default:
 		errno = EINVAL;
 		return -1;
```
