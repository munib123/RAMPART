# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2609_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2609_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 20-43 of the vulnerable file.

|    but WITHOUT ANY WARRANTY; without even the implied warranty of
|    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|    GNU General Public License for more details.
|
|    You should have received a copy of the GNU General Public License
|    along with Bento4|GPL; see the file COPYING.  If not, write to the
|    Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
|    02111-1307, USA.
|
****************************************************************/

#ifndef _AP4_VERSION_H_
#define _AP4_VERSION_H_

/*----------------------------------------------------------------------
|   version constants
+---------------------------------------------------------------------*/
/**
 * Version number of the SDK
 */
#define AP4_VERSION        0x01050000
#define AP4_VERSION_STRING "1.5.0.0"

#endif // _AP4_VERSION_H_
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,7 +37,7 @@
 /**
  * Version number of the SDK
  */
-#define AP4_VERSION        0x01050000
-#define AP4_VERSION_STRING "1.5.0.0"
+#define AP4_VERSION        0x01050001
+#define AP4_VERSION_STRING "1.5.0.1"
 
 #endif // _AP4_VERSION_H_
```
