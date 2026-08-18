# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4019_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4019_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 17-57 of the vulnerable file.

 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA.
 */

#include <config.h>
#include "exif-mnote-data-olympus.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libexif/exif-utils.h>
#include <libexif/exif-data.h>

/* Uncomment this to fix a problem with Sanyo MakerNotes. It's probably best
 * not to in most cases because it seems to only affect the thumbnail tag
 * which is duplicated in IFD 1, and fixing the offset could actually cause
 * problems with other software that expects the broken form.
 */
/*#define EXIF_OVERCOME_SANYO_OFFSET_BUG */

static enum OlympusVersion
exif_mnote_data_olympus_identify_variant (const unsigned char *buf,
		unsigned int buf_size);


static void
exif_mnote_data_olympus_clear (ExifMnoteDataOlympus *n)
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,6 +35,8 @@
  */
 /*#define EXIF_OVERCOME_SANYO_OFFSET_BUG */
 
+#define CHECKOVERFLOW(offset,datasize,structsize) (( offset >= datasize) || (structsize > datasize) || (offset > datasize - structsize ))
+
 static enum OlympusVersion
 exif_mnote_data_olympus_identify_variant (const unsigned char *buf,
 		unsigned int buf_size);
@@ -245,7 +247,7 @@
 		return;
 	}
 	o2 = 6 + n->offset; /* Start of interesting data */
-	if ((o2 + 10 < o2) || (o2 + 10 < 10) || (o2 + 10 > buf_size)) {
+	if (CHECKOVERFLOW(o2,buf_size,10)) {
 		exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 			  "ExifMnoteDataOlympus", "Short MakerNote");
 		return;
@@ -300,7 +302,7 @@
 		/* Olympus S760, S770 */
 		datao = o2;
 		o2 += 8;
-		if ((o2 + 4 < o2) || (o2 + 4 < 4) || (o2 + 4 > buf_size)) return;
+		if (CHECKOVERFLOW(o2,buf_size,4)) return;
 		exif_log (en->log, EXIF_LOG_CODE_DEBUG, "ExifMnoteDataOlympus",
 			"Parsing Olympus maker note v2 (0x%02x, %02x, %02x, %02x)...",
 			buf[o2 + 0], buf[o2 + 1], buf[o2 + 2], buf[o2 + 3]);
@@ -341,7 +343,7 @@
 
 	case nikonV2:
 		o2 += 6;
-		if ((o2 + 12 < o2) || (o2 + 12 < 12) || (o2 + 12 > buf_size)) return;
+		if (CHECKOVERFLOW(o2,buf_size,12)) return;
 		exif_log (en->log, EXIF_LOG_CODE_DEBUG, "ExifMnoteDataOlympus",
 			"Parsing Nikon maker note v2 (0x%02x, %02x, %02x, "
 			"%02x, %02x, %02x, %02x, %02x)...",
@@ -399,7 +401,7 @@
 	}
 
 	/* Sanity check the offset */
-	if ((o2 + 2 < o2) || (o2 + 2 < 2) || (o2 + 2 > buf_size)) {
+	if (CHECKOVERFLOW(o2,buf_size,2)) {
 		exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 			  "ExifMnoteOlympus", "Short MakerNote");
 		return;
@@ -423,7 +425,7 @@
 	tcount = 0;
 	for (i = c, o = o2; i; --i, o += 12) {
 		size_t s;
-		if ((o + 12 < o) || (o + 12 < 12) || (o + 12 > buf_size)) {
+		if (CHECKOVERFLOW(o, buf_size, 12)) {
 			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 				  "ExifMnoteOlympus", "Short MakerNote");
 			break;
@@ -444,6 +446,14 @@
 		    n->entries[tcount].components,
 		    (int)exif_format_get_size(n->entries[tcount].format)); */
 
+	    /* Check if we overflow the multiplication. Use buf_size as the max size for integer overflow detection,
+	     * we will check the buffer sizes closer later. */
+	    if (exif_format_get_size (n->entries[tcount].format) &&
+		buf_size / exif_format_get_size (n->entries[tcount].format) < n->entries[tcount].components
+	    ) {
+		exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA, "ExifMnoteOlympus", "Tag size overflow detected (%u * %lu)", exif_format_get_size (n->entries[tcount].format), n->entries[tcount].components);
+		continue;
+	    }
 	    /*
 	     * Size? If bigger than 4 bytes, the actual data is not
 	     * in the entry but somewhere else (offset).
@@ -462,7 +472,7 @@
 				 * tag in its MakerNote. The offset is actually the absolute
 				 * position in the file instead of the position within the IFD.
 				 */
-			    if (dataofs + s > buf_size && n->version == sanyoV1) {
+			    if (dataofs > (buf_size - s) && n->version == sanyoV1) {
 					/* fix pointer */
 					dataofs -= datao + 6;
 					exif_log (en->log, EXIF_LOG_CODE_DEBUG,
@@ -471,8 +481,7 @@
 			    }
 #endif
 			}
-			if ((dataofs + s < dataofs) || (dataofs + s < s) || 
-			    (dataofs + s > buf_size)) {
+			if (CHECKOVERFLOW(dataofs, buf_size, s)) {
 				exif_log (en->log, EXIF_LOG_CODE_DEBUG,
 					  "ExifMnoteOlympus",
 					  "Tag data past end of buffer (%u > %u)",
```
