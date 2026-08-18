# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 477_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `477_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 18-58 of the vulnerable file.

 * Boston, MA  02110-1301  USA.
 */

#include <config.h>

#include <libexif/exif-mnote-data.h>
#include <libexif/exif-data.h>
#include <libexif/exif-ifd.h>
#include <libexif/exif-mnote-data-priv.h>
#include <libexif/exif-utils.h>
#include <libexif/exif-loader.h>
#include <libexif/exif-log.h>
#include <libexif/i18n.h>
#include <libexif/exif-system.h>

#include <libexif/canon/exif-mnote-data-canon.h>
#include <libexif/fuji/exif-mnote-data-fuji.h>
#include <libexif/olympus/exif-mnote-data-olympus.h>
#include <libexif/pentax/exif-mnote-data-pentax.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#undef JPEG_MARKER_SOI
#define JPEG_MARKER_SOI  0xd8
#undef JPEG_MARKER_APP0
#define JPEG_MARKER_APP0 0xe0
#undef JPEG_MARKER_APP1
#define JPEG_MARKER_APP1 0xe1

static const unsigned char ExifHeader[] = {0x45, 0x78, 0x69, 0x66, 0x00, 0x00};

struct _ExifDataPrivate
{
	ExifByteOrder order;

	ExifMnoteData *md;

	ExifLog *log;
	ExifMem *mem;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,6 +35,7 @@
 #include <libexif/olympus/exif-mnote-data-olympus.h>
 #include <libexif/pentax/exif-mnote-data-pentax.h>
 
+#include <math.h>
 #include <stdlib.h>
 #include <stdio.h>
 #include <string.h>
@@ -350,6 +351,20 @@
 	break;						\
 }
 
+/*! Calculate the recursion cost added by one level of IFD loading.
+ *
+ * The work performed is related to the cost in the exponential relation
+ *   work=1.1**cost
+ */
+static unsigned int
+level_cost(unsigned int n)
+{
+    static const double log_1_1 = 0.09531017980432493;
+
+	/* Adding 0.1 protects against the case where n==1 */
+	return ceil(log(n + 0.1)/log_1_1);
+}
+
 /*! Load data for an IFD.
  *
  * \param[in,out] data #ExifData
@@ -357,13 +372,13 @@
  * \param[in] d pointer to buffer containing raw IFD data
  * \param[in] ds size of raw data in buffer at \c d
  * \param[in] offset offset into buffer at \c d at which IFD starts
- * \param[in] recursion_depth number of times this function has been
- * recursively called without returning
+ * \param[in] recursion_cost factor indicating how expensive this recursive
+ * call could be
  */
 static void
 exif_data_load_data_content (ExifData *data, ExifIfd ifd,
 			     const unsigned char *d,
-			     unsigned int ds, unsigned int offset, unsigned int recursion_depth)
+			     unsigned int ds, unsigned int offset, unsigned int recursion_cost)
 {
 	ExifLong o, thumbnail_offset = 0, thumbnail_length = 0;
 	ExifShort n;
@@ -378,9 +393,20 @@
 	if ((((int)ifd) < 0) || ( ((int)ifd) >= EXIF_IFD_COUNT))
 	  return;
 
-	if (recursion_depth > 12) {
+	if (recursion_cost > 170) {
+		/*
+		 * recursion_cost is a logarithmic-scale indicator of how expensive this
+		 * recursive call might end up being. It is an indicator of the depth of
+		 * recursion as well as the potential for worst-case future recursive
+		 * calls. Since it's difficult to tell ahead of time how often recursion
+		 * will occur, this assumes the worst by assuming every tag could end up
+		 * causing recursion.
+		 * The value of 170 was chosen to limit typical EXIF structures to a
+		 * recursive depth of about 6, but pathological ones (those with very
+		 * many tags) to only 2.
+		 */
 		exif_log (data->priv->log, EXIF_LOG_CODE_CORRUPT_DATA, "ExifData",
-			  "Deep recursion detected!");
+			  "Deep/expensive recursion detected!");
 		return;
 	}
 
@@ -422,15 +448,18 @@
 			switch (tag) {
 			case EXIF_TAG_EXIF_IFD_POINTER:
 				CHECK_REC (EXIF_IFD_EXIF);
-				exif_data_load_data_content (data, EXIF_IFD_EXIF, d, ds, o, recursion_depth + 1);
+				exif_data_load_data_content (data, EXIF_IFD_EXIF, d, ds, o,
+					recursion_cost + level_cost(n));
 				break;
 			case EXIF_TAG_GPS_INFO_IFD_POINTER:
 				CHECK_REC (EXIF_IFD_GPS);
-				exif_data_load_data_content (data, EXIF_IFD_GPS, d, ds, o, recursion_depth + 1);
+				exif_data_load_data_content (data, EXIF_IFD_GPS, d, ds, o,
+					recursion_cost + level_cost(n));
 				break;
 			case EXIF_TAG_INTEROPERABILITY_IFD_POINTER:
 				CHECK_REC (EXIF_IFD_INTEROPERABILITY);
-				exif_data_load_data_content (data, EXIF_IFD_INTEROPERABILITY, d, ds, o, recursion_depth + 1);
+				exif_data_load_data_content (data, EXIF_IFD_INTEROPERABILITY, d, ds, o,
+					recursion_cost + level_cost(n));
 				break;
 			case EXIF_TAG_JPEG_INTERCHANGE_FORMAT:
 				thumbnail_offset = o;
```
