# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4019_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4019_1`)

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

#include <stdlib.h>
#include <string.h>


#include <config.h>
#include <libexif/exif-byte-order.h>
#include <libexif/exif-utils.h>

#include "exif-mnote-data-fuji.h"

struct _MNoteFujiDataPrivate {
	ExifByteOrder order;
};

static void
exif_mnote_data_fuji_clear (ExifMnoteDataFuji *n)
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,8 @@
 #include <libexif/exif-utils.h>
 
 #include "exif-mnote-data-fuji.h"
+
+#define CHECKOVERFLOW(offset,datasize,structsize) (( offset >= datasize) || (structsize > datasize) || (offset > datasize - structsize ))
 
 struct _MNoteFujiDataPrivate {
 	ExifByteOrder order;
@@ -162,16 +164,16 @@
 		return;
 	}
 	datao = 6 + n->offset;
-	if ((datao + 12 < datao) || (datao + 12 < 12) || (datao + 12 > buf_size)) {
+	if (CHECKOVERFLOW(datao, buf_size, 12)) {
 		exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 			  "ExifMnoteDataFuji", "Short MakerNote");
 		return;
 	}
 
 	n->order = EXIF_BYTE_ORDER_INTEL;
+
 	datao += exif_get_long (buf + datao + 8, EXIF_BYTE_ORDER_INTEL);
-	if ((datao + 2 < datao) || (datao + 2 < 2) ||
-	    (datao + 2 > buf_size)) {
+	if (CHECKOVERFLOW(datao, buf_size, 2)) {
 		exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 			  "ExifMnoteDataFuji", "Short MakerNote");
 		return;
@@ -195,7 +197,8 @@
 	tcount = 0;
 	for (i = c, o = datao; i; --i, o += 12) {
 		size_t s;
-		if ((o + 12 < o) || (o + 12 < 12) || (o + 12 > buf_size)) {
+
+		if (CHECKOVERFLOW(o, buf_size, 12)) {
 			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 				  "ExifMnoteDataFuji", "Short MakerNote");
 			break;
@@ -210,6 +213,15 @@
 			  "Loading entry 0x%x ('%s')...", n->entries[tcount].tag,
 			  mnote_fuji_tag_get_name (n->entries[tcount].tag));
 
+		/* Check if we overflow the multiplication. Use buf_size as the max size for integer overflow detection,
+		 * we will check the buffer sizes closer later. */
+		if (	exif_format_get_size (n->entries[tcount].format) &&
+			buf_size / exif_format_get_size (n->entries[tcount].format) < n->entries[tcount].components
+		) {
+			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
+					  "ExifMnoteDataFuji", "Tag size overflow detected (%u * %lu)", exif_format_get_size (n->entries[tcount].format), n->entries[tcount].components);
+			continue;
+		}
 		/*
 		 * Size? If bigger than 4 bytes, the actual data is not
 		 * in the entry but somewhere else (offset).
@@ -221,8 +233,8 @@
 			if (s > 4)
 				/* The data in this case is merely a pointer */
 				dataofs = exif_get_long (buf + dataofs, n->order) + 6 + n->offset;
-			if ((dataofs + s < dataofs) || (dataofs + s < s) ||
-				(dataofs + s >= buf_size)) {
+
+			if (CHECKOVERFLOW(dataofs, buf_size, s)) {
 				exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 						  "ExifMnoteDataFuji", "Tag data past end of "
 					  "buffer (%u >= %u)", (unsigned)(dataofs + s), buf_size);
```
