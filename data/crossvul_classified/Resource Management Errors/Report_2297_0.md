# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2297_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2297_0`)

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
 * @(#)$File: file.h,v 1.154 2014/09/10 18:41:51 christos Exp $
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
- * @(#)$File: file.h,v 1.154 2014/09/10 18:41:51 christos Exp $
+ * @(#)$File: file.h,v 1.155 2014/10/11 15:03:16 christos Exp $
  */
 
 #ifndef __file_h__
@@ -495,6 +495,14 @@
 protected void file_regfree(file_regex_t *);
 protected void file_regerror(file_regex_t *, int, struct magic_set *);
 
+typedef struct {
+	char *buf;
+	uint32_t offset;
+} file_pushbuf_t;
+
+protected file_pushbuf_t *file_push_buffer(struct magic_set *);
+protected char  *file_pop_buffer(struct magic_set *, file_pushbuf_t *);
+
 #ifndef COMPILE_ONLY
 extern const char *file_names[];
 extern const size_t file_nnames;
```
