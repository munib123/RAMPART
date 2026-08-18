# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 4021_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4021_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 14-54 of the vulnerable file.

 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA.
 */

#include <config.h>
#include "exif-mnote-data-canon.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libexif/exif-byte-order.h>
#include <libexif/exif-utils.h>
#include <libexif/exif-data.h>

#define CHECKOVERFLOW(offset,datasize,structsize) (( offset >= datasize) || (structsize > datasize) || (offset > datasize - structsize ))

static void
exif_mnote_data_canon_clear (ExifMnoteDataCanon *n)
{
	ExifMnoteData *d = (ExifMnoteData *) n;
	unsigned int i;

	if (!n) return;

	if (n->entries) {
		for (i = 0; i < n->count; i++)
			if (n->entries[i].data) {
				exif_mem_free (d->mem, n->entries[i].data);
				n->entries[i].data = NULL;
			}
		exif_mem_free (d->mem, n->entries);
		n->entries = NULL;
		n->count = 0;
	}
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,9 @@
 
 #define CHECKOVERFLOW(offset,datasize,structsize) (( offset >= datasize) || (structsize > datasize) || (offset > datasize - structsize ))
 
+/* Total size limit to prevent abuse by DoS */
+#define FAILSAFE_SIZE_MAX 1000000L
+
 static void
 exif_mnote_data_canon_clear (ExifMnoteDataCanon *n)
 {
@@ -204,6 +207,7 @@
 	ExifMnoteDataCanon *n = (ExifMnoteDataCanon *) ne;
 	ExifShort c;
 	size_t i, tcount, o, datao;
+	long failsafe_size = 0;
 
 	if (!n || !buf || !buf_size) {
 		exif_log (ne->log, EXIF_LOG_CODE_CORRUPT_DATA,
@@ -295,6 +299,23 @@
 			memcpy (n->entries[tcount].data, buf + dataofs, s);
 		}
 
+		/* Track the size of decoded tag data. A malicious file could
+		 * be crafted to cause extremely large values here without
+		 * tripping any buffer range checks.  This is especially bad
+		 * with the libexif representation of Canon MakerNotes because
+		 * some arrays are turned into individual tags that the
+		 * application must loop around. */
+		failsafe_size += mnote_canon_entry_count_values(&n->entries[tcount]);
+
+		if (failsafe_size > FAILSAFE_SIZE_MAX) {
+			/* Abort if the total size of the data in the tags extraordinarily large, */
+			exif_mem_free (ne->mem, n->entries[tcount].data);
+			exif_log (ne->log, EXIF_LOG_CODE_CORRUPT_DATA,
+					  "ExifMnoteCanon", "Failsafe tag size overflow (%lu > %ld)",
+					  failsafe_size, FAILSAFE_SIZE_MAX);
+			break;
+		}
+
 		/* Tag was successfully parsed */
 		++tcount;
 	}
```
