# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 252_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `252_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 11-33 of the vulnerable file.

 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _MUTT_BASE64_H
#define _MUTT_BASE64_H

#include <stdio.h>

extern const int Index64[];

#define base64val(c) Index64[(unsigned int) (c)]

size_t mutt_b64_encode(char *out, const char *cin, size_t len, size_t olen);
int    mutt_b64_decode(char *out, const char *in);

#endif /* _MUTT_BASE64_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,6 @@
 #define base64val(c) Index64[(unsigned int) (c)]
 
 size_t mutt_b64_encode(char *out, const char *cin, size_t len, size_t olen);
-int    mutt_b64_decode(char *out, const char *in);
+int    mutt_b64_decode(char *out, const char *in, size_t olen);
 
 #endif /* _MUTT_BASE64_H */
```
