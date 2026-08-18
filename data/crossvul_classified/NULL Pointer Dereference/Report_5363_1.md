# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5363_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5363_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 60-100 of the vulnerable file.

 * 
 * __END_OF_JASPER_LICENSE__
 */

/*
 * Windows Bitmap File Library
 *
 * $Id$
 */

/******************************************************************************\
* Includes.
\******************************************************************************/

#include <assert.h>

#include "jasper/jas_types.h"
#include "jasper/jas_stream.h"
#include "jasper/jas_image.h"
#include "jasper/jas_malloc.h"

#include "bmp_cod.h"

/******************************************************************************\
* Local prototypes.
\******************************************************************************/

static int bmp_gethdr(jas_stream_t *in, bmp_hdr_t *hdr);
static bmp_info_t *bmp_getinfo(jas_stream_t *in);
static int bmp_getdata(jas_stream_t *in, bmp_info_t *info, jas_image_t *image);
static int bmp_getint16(jas_stream_t *in, int_fast16_t *val);
static int bmp_getint32(jas_stream_t *in, int_fast32_t *val);
static int bmp_gobble(jas_stream_t *in, long n);

/******************************************************************************\
* Interface functions.
\******************************************************************************/

jas_image_t *bmp_decode(jas_stream_t *in, char *optstr)
{
	jas_image_t *image;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,6 +77,7 @@
 #include "jasper/jas_stream.h"
 #include "jasper/jas_image.h"
 #include "jasper/jas_malloc.h"
+#include "jasper/jas_debug.h"
 
 #include "bmp_cod.h"
 
@@ -122,12 +123,22 @@
 		jas_eprintf("cannot get header\n");
 		return 0;
 	}
+	JAS_DBGLOG(1, (
+	  "BMP header: magic 0x%x; siz %d; res1 %d; res2 %d; off %d\n",
+	  hdr.magic, hdr.siz, hdr.reserved1, hdr.reserved2, hdr.off
+	  ));
 
 	/* Read the bitmap information. */
 	if (!(info = bmp_getinfo(in))) {
 		jas_eprintf("cannot get info\n");
 		return 0;
 	}
+	JAS_DBGLOG(1,
+	  ("BMP information: len %d; width %d; height %d; numplanes %d; "
+	  "depth %d; enctype %d; siz %d; hres %d; vres %d; numcolors %d; "
+	  "mincolors %d\n", info->len, info->width, info->height, info->numplanes,
+	  info->depth, info->enctype, info->siz, info->hres, info->vres,
+	  info->numcolors, info->mincolors));
 
 	/* Ensure that we support this type of BMP file. */
 	if (!bmp_issupported(&hdr, info)) {
@@ -440,7 +451,7 @@
 		if ((c = jas_stream_getc(in)) == EOF) {
 			return -1;
 		}
-		v |= (c << 24);
+		v |= (JAS_CAST(uint_fast32_t, c) << 24);
 		if (--n <= 0) {
 			break;
 		}
```
