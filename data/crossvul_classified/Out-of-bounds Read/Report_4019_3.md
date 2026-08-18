# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4019_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4019_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 10-50 of the vulnerable file.

 * This library is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details. 
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA.
 */

#include "config.h"
#include "exif-mnote-data-pentax.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libexif/exif-byte-order.h>
#include <libexif/exif-utils.h>

static void
exif_mnote_data_pentax_clear (ExifMnoteDataPentax *n)
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
@@ -27,6 +27,8 @@
 
 #include <libexif/exif-byte-order.h>
 #include <libexif/exif-utils.h>
+
+#define CHECKOVERFLOW(offset,datasize,structsize) (( offset >= datasize) || (structsize > datasize) || (offset > datasize - structsize ))
 
 static void
 exif_mnote_data_pentax_clear (ExifMnoteDataPentax *n)
@@ -224,7 +226,7 @@
 		return;
 	}
 	datao = 6 + n->offset;
-	if ((datao + 8 < datao) || (datao + 8 < 8) || (datao + 8 > buf_size)) {
+	if (CHECKOVERFLOW(datao, buf_size, 8)) {
 		exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 			  "ExifMnoteDataPentax", "Short MakerNote");
 		return;
@@ -277,7 +279,8 @@
 	tcount = 0;
 	for (i = c, o = datao; i; --i, o += 12) {
 		size_t s;
-		if ((o + 12 < o) || (o + 12 < 12) || (o + 12 > buf_size)) {
+
+		if (CHECKOVERFLOW(o,buf_size,12)) {
 			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 				  "ExifMnoteDataPentax", "Short MakerNote");
 			break;
@@ -292,6 +295,15 @@
 			  "Loading entry 0x%x ('%s')...", n->entries[tcount].tag,
 			  mnote_pentax_tag_get_name (n->entries[tcount].tag));
 
+		/* Check if we overflow the multiplication. Use buf_size as the max size for integer overflow detection,
+		 * we will check the buffer sizes closer later. */
+		if (	exif_format_get_size (n->entries[tcount].format) &&
+			buf_size / exif_format_get_size (n->entries[tcount].format) < n->entries[tcount].components
+		) {
+			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
+				  "ExifMnoteDataPentax", "Tag size overflow detected (%u * %lu)", exif_format_get_size (n->entries[tcount].format), n->entries[tcount].components);
+			break;
+		}
 		/*
 		 * Size? If bigger than 4 bytes, the actual data is not
 		 * in the entry but somewhere else (offset).
@@ -304,8 +316,8 @@
 			if (s > 4)
 				/* The data in this case is merely a pointer */
 			   	dataofs = exif_get_long (buf + dataofs, n->order) + 6;
-			if ((dataofs + s < dataofs) || (dataofs + s < s) ||
-				(dataofs + s > buf_size)) {
+
+			if (CHECKOVERFLOW(dataofs, buf_size, s)) {
 				exif_log (en->log, EXIF_LOG_CODE_DEBUG,
 						  "ExifMnoteDataPentax", "Tag data past end "
 					  "of buffer (%u > %u)", (unsigned)(dataofs + s), buf_size);
```
