# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 913_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `913_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 12-52 of the vulnerable file.

 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "regint.h"

static void
conv_ext0be32(const UChar* s, const UChar* end, UChar* conv)
{
  while (s < end) {
    *conv++ = '\0';
    *conv++ = '\0';
    *conv++ = '\0';
    *conv++ = *s++;
  }
}

static void
conv_ext0le32(const UChar* s, const UChar* end, UChar* conv)
{
  while (s < end) {
    *conv++ = *s++;
    *conv++ = '\0';
    *conv++ = '\0';
    *conv++ = '\0';
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
 
 #include "regint.h"
 
+#if 0
 static void
 conv_ext0be32(const UChar* s, const UChar* end, UChar* conv)
 {
@@ -158,6 +159,7 @@
 
   return ONIGERR_NOT_SUPPORTED_ENCODING_COMBINATION;
 }
+#endif
 
 extern int
 onig_new_deluxe(regex_t** reg, const UChar* pattern, const UChar* pattern_end,
@@ -169,9 +171,7 @@
   if (IS_NOT_NULL(einfo)) einfo->par = (UChar* )NULL;
 
   if (ci->pattern_enc != ci->target_enc) {
-    r = conv_encoding(ci->pattern_enc, ci->target_enc, pattern, pattern_end,
-                      &cpat, &cpat_end);
-    if (r != 0) return r;
+    return ONIGERR_NOT_SUPPORTED_ENCODING_COMBINATION;
   }
   else {
     cpat     = (UChar* )pattern;
```
