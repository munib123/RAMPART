# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 669_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `669_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 12-52 of the vulnerable file.

 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#if !defined( _LIBEVT_LIBFVALUE_H )
#define _LIBEVT_LIBFVALUE_H

#include <common.h>

/* Define HAVE_LOCAL_LIBFVALUE for local use of libfvalue
 */
#if defined( HAVE_LOCAL_LIBFVALUE )

#include <libfvalue_codepage.h>
#include <libfvalue_definitions.h>
#include <libfvalue_floating_point.h>
#include <libfvalue_integer.h>
#include <libfvalue_split_utf16_string.h>
#include <libfvalue_split_utf8_string.h>
#include <libfvalue_string.h>
#include <libfvalue_table.h>
#include <libfvalue_types.h>
#include <libfvalue_value.h>
#include <libfvalue_value_type.h>
#include <libfvalue_utf16_string.h>
#include <libfvalue_utf8_string.h>

#else

/* If libtool DLL support is enabled set LIBFVALUE_DLL_IMPORT
 * before including libfvalue.h
 */
#if defined( _WIN32 ) && defined( DLL_IMPORT )
#define LIBFVALUE_DLL_IMPORT
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
 #if defined( HAVE_LOCAL_LIBFVALUE )
 
 #include <libfvalue_codepage.h>
+#include <libfvalue_data_handle.h>
 #include <libfvalue_definitions.h>
 #include <libfvalue_floating_point.h>
 #include <libfvalue_integer.h>
```
