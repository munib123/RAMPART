# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4019_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4019_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 12-52 of the vulnerable file.

 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
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
@@ -29,6 +29,8 @@
 #include <libexif/exif-byte-order.h>
 #include <libexif/exif-utils.h>
 #include <libexif/exif-data.h>
+
+#define CHECKOVERFLOW(offset,datasize,structsize) (( offset >= datasize) || (structsize > datasize) || (offset > datasize - structsize ))
 
 static void
 exif_mnote_data_canon_clear (ExifMnoteDataCanon *n)
@@ -209,7 +211,7 @@
 		return;
 	}
 	datao = 6 + n->offset;
-	if ((datao + 2 < datao) || (datao + 2 < 2) || (datao + 2 > buf_size)) {
+	if (CHECKOVERFLOW(datao, buf_size, 2)) {
 		exif_log (ne->log, EXIF_LOG_CODE_CORRUPT_DATA,
 			  "ExifMnoteCanon", "Short MakerNote");
 		return;
@@ -233,11 +235,12 @@
 	tcount = 0;
 	for (i = c, o = datao; i; --i, o += 12) {
 		size_t s;
-		if ((o + 12 < o) || (o + 12 < 12) || (o + 12 > buf_size)) {
+
+		if (CHECKOVERFLOW(o,buf_size,12)) {
 			exif_log (ne->log, EXIF_LOG_CODE_CORRUPT_DATA,
 				"ExifMnoteCanon", "Short MakerNote");
 			break;
-	        }
+		}
 
 		n->entries[tcount].tag        = exif_get_short (buf + o, n->order);
 		n->entries[tcount].format     = exif_get_short (buf + o + 2, n->order);
@@ -247,6 +250,16 @@
 		exif_log (ne->log, EXIF_LOG_CODE_DEBUG, "ExifMnoteCanon",
 			"Loading entry 0x%x ('%s')...", n->entries[tcount].tag,
 			 mnote_canon_tag_get_name (n->entries[tcount].tag));
+
+		/* Check if we overflow the multiplication. Use buf_size as the max size for integer overflow detection,
+		 * we will check the buffer sizes closer later. */
+		if (	exif_format_get_size (n->entries[tcount].format) &&
+			buf_size / exif_format_get_size (n->entries[tcount].format) < n->entries[tcount].components
+		) {
+			exif_log (ne->log, EXIF_LOG_CODE_CORRUPT_DATA,
+				  "ExifMnoteCanon", "Tag size overflow detected (%u * %lu)", exif_format_get_size (n->entries[tcount].format), n->entries[tcount].components);
+			continue;
+		}
 
 		/*
 		 * Size? If bigger than 4 bytes, the actual data is not
@@ -264,7 +277,8 @@
 		} else {
 			size_t dataofs = o + 8;
 			if (s > 4) dataofs = exif_get_long (buf + dataofs, n->order) + 6;
-			if ((dataofs + s < s) || (dataofs + s < dataofs) || (dataofs + s > buf_size)) {
+
+			if (CHECKOVERFLOW(dataofs, buf_size, s)) {
 				exif_log (ne->log, EXIF_LOG_CODE_DEBUG,
 					"ExifMnoteCanon",
 					"Tag data past end of buffer (%u > %u)",
```
