# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1508_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1508_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 10-50 of the vulnerable file.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "libabrt.h"

#define ABRT_CONF "abrt.conf"

char *        g_settings_sWatchCrashdumpArchiveDir = NULL;
unsigned int  g_settings_nMaxCrashReportsSize = 1000;
char *        g_settings_dump_location = NULL;
bool          g_settings_delete_uploaded = 0;
bool          g_settings_autoreporting = 0;
char *        g_settings_autoreporting_event = NULL;
bool          g_settings_shortenedreporting = 0;

void free_abrt_conf_data()
{
    free(g_settings_sWatchCrashdumpArchiveDir);
    g_settings_sWatchCrashdumpArchiveDir = NULL;

    free(g_settings_dump_location);
    g_settings_dump_location = NULL;
}

static void ParseCommon(map_string_t *settings, const char *conf_filename)
{
    const char *value;

    value = get_map_string_item_or_NULL(settings, "WatchCrashdumpArchiveDir");
    if (value)
    {
        g_settings_sWatchCrashdumpArchiveDir = xstrdup(value);
        remove_map_string_item(settings, "WatchCrashdumpArchiveDir");
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,7 @@
 bool          g_settings_autoreporting = 0;
 char *        g_settings_autoreporting_event = NULL;
 bool          g_settings_shortenedreporting = 0;
+bool          g_settings_privatereports = true;
 
 void free_abrt_conf_data()
 {
@@ -102,6 +103,13 @@
     else
         g_settings_shortenedreporting = 0;
 
+    value = get_map_string_item_or_NULL(settings, "PrivateReports");
+    if (value)
+    {
+        g_settings_privatereports = string_to_bool(value);
+        remove_map_string_item(settings, "PrivateReports");
+    }
+
     GHashTableIter iter;
     const char *name;
     /*char *value; - already declared */
```
