# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2392_6
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2392_6`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 10-50 of the vulnerable file.

 *    notice immediately at the beginning of the file, without modification,
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
/*
 * file.h - definitions for file(1) program
 * @(#)$File: file.h,v 1.161 2014/12/04 15:56:46 christos Exp $
 */

#ifndef __file_h__
#define __file_h__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WIN32
  #ifdef _WIN64
    #define SIZE_T_FORMAT "I64"
  #else
    #define SIZE_T_FORMAT ""
  #endif
  #define INT64_T_FORMAT "I64"
#else
  #define SIZE_T_FORMAT "z"
  #define INT64_T_FORMAT "ll"
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
  */
 /*
  * file.h - definitions for file(1) program
- * @(#)$File: file.h,v 1.161 2014/12/04 15:56:46 christos Exp $
+ * @(#)$File: file.h,v 1.162 2014/12/11 12:34:24 christos Exp $
  */
 
 #ifndef __file_h__
@@ -407,10 +407,12 @@
 	uint16_t name_max;
 	uint16_t elf_shnum_max;
 	uint16_t elf_phnum_max;
+	uint16_t elf_notes_max;
 #define	FILE_INDIR_MAX			15
 #define	FILE_NAME_MAX			30
 #define	FILE_ELF_SHNUM_MAX		32768
 #define	FILE_ELF_PHNUM_MAX		128
+#define	FILE_ELF_NOTES_MAX		256
 };
 
 /* Type for Unicode characters */
```
