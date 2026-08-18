# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2802_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2802_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public
 *  License along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *  Author: Darin Adler <darin@bentspoon.com>
 */

#include <config.h>

#include "nautilus-directory-notify.h"
#include "nautilus-directory-private.h"
#include "nautilus-file-attributes.h"
#include "nautilus-file-private.h"
#include "nautilus-file-utilities.h"
#include "nautilus-signaller.h"
#include "nautilus-global-preferences.h"
#include "nautilus-link.h"
#include "nautilus-profile.h"
#include <eel/eel-glib-extensions.h>
#include <gtk/gtk.h>
#include <libxml/parser.h>
#include <stdio.h>
#include <stdlib.h>

/* turn this on to see messages about each load_directory call: */
#if 0
#define DEBUG_LOAD_DIRECTORY
#endif

/* turn this on to check if async. job calls are balanced */
#if 0
#define DEBUG_ASYNC_JOBS
#endif

/* turn this on to log things starting and stopping */
#if 0
#define DEBUG_START_STOP
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,7 @@
 #include "nautilus-global-preferences.h"
 #include "nautilus-link.h"
 #include "nautilus-profile.h"
+#include "nautilus-metadata.h"
 #include <eel/eel-glib-extensions.h>
 #include <gtk/gtk.h>
 #include <libxml/parser.h>
@@ -3580,13 +3581,17 @@
 {
     GFile *location;
     gboolean res;
+    g_autofree gchar* trusted = NULL;
 
     if (!is_launcher)
     {
         return TRUE;
     }
 
-    if (nautilus_file_can_execute (file))
+    trusted = nautilus_file_get_metadata (file,
+                                          NAUTILUS_METADATA_KEY_DESKTOP_FILE_TRUSTED,
+                                          NULL);
+    if (nautilus_file_can_execute (file) && trusted != NULL)
     {
         return TRUE;
     }
```
