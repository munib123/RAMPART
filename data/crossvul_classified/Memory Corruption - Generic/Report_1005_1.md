# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1005_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1005_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 23-44 of the vulnerable file.

 *
 * You should have received a copy of the GNU General Public License
 * along with pdfresurrect.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/

#ifndef MAIN_H_INCLUDE
#define MAIN_H_INCLUDE

#include <stdio.h>


#define EXEC_NAME "pdfresurrect"
#define VER_MAJOR "0"
#define VER_MINOR "18b"
#define VER       VER_MAJOR"."VER_MINOR 


#define TAG "[pdfresurrect]"
#define ERR(...) {fprintf(stderr, TAG" -- Error -- " __VA_ARGS__);}


#endif /* MAIN_H_INCLUDE */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,5 +40,7 @@
 #define TAG "[pdfresurrect]"
 #define ERR(...) {fprintf(stderr, TAG" -- Error -- " __VA_ARGS__);}
 
+/* Returns a zero'd buffer of 'size' bytes or exits in failure. */
+extern void *safe_calloc(size_t bytes);
 
 #endif /* MAIN_H_INCLUDE */
```
