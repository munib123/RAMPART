# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2144_9
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2144_9`)

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
 * @(#)$File: file.h,v 1.150 2014/05/05 20:53:10 christos Exp $
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
- * @(#)$File: file.h,v 1.150 2014/05/05 20:53:10 christos Exp $
+ * @(#)$File: file.h,v 1.151 2014/05/14 23:15:42 christos Exp $
  */
 
 #ifndef __file_h__
@@ -133,7 +133,7 @@
 #define MAXstring 64		/* max len of "string" types */
 
 #define MAGICNO		0xF11E041C
-#define VERSIONNO	11
+#define VERSIONNO	12
 #define FILE_MAGICSIZE	248
 
 #define	FILE_LOAD	0
@@ -321,6 +321,7 @@
 #define PSTRING_2_LE				BIT(9)
 #define PSTRING_4_BE				BIT(10)
 #define PSTRING_4_LE				BIT(11)
+#define REGEX_LINE_COUNT			BIT(11)
 #define PSTRING_LEN	\
     (PSTRING_1_BE|PSTRING_2_LE|PSTRING_2_BE|PSTRING_4_LE|PSTRING_4_BE)
 #define PSTRING_LENGTH_INCLUDES_ITSELF		BIT(12)
```
