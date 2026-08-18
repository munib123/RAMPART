# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5370_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5370_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 90-130 of the vulnerable file.

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
	bmp_hdr_t hdr;
	bmp_info_t *info;
	uint_fast16_t cmptno;
	jas_image_cmptparm_t cmptparms[3];
	jas_image_cmptparm_t *cmptparm;
	uint_fast16_t numcmpts;
	long n;

	if (optstr) {
		jas_eprintf("warning: ignoring BMP decoder options\n");
	}

	jas_eprintf(
	  "THE BMP FORMAT IS NOT FULLY SUPPORTED!\n"
	  "THAT IS, THE JASPER SOFTWARE CANNOT DECODE ALL TYPES OF BMP DATA.\n"
	  "IF YOU HAVE ANY PROBLEMS, PLEASE TRY CONVERTING YOUR IMAGE DATA\n"
	  "TO THE PNM FORMAT, AND USING THIS FORMAT INSTEAD.\n"
	  );

	/* Read the bitmap header. */
	if (bmp_gethdr(in, &hdr)) {
		jas_eprintf("cannot get header\n");
		return 0;
	}
	JAS_DBGLOG(1, (
	  "BMP header: magic 0x%x; siz %d; res1 %d; res2 %d; off %d\n",
	  hdr.magic, hdr.siz, hdr.reserved1, hdr.reserved2, hdr.off
	  ));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,6 +107,9 @@
 	uint_fast16_t numcmpts;
 	long n;
 
+	image = 0;
+	info = 0;
+
 	if (optstr) {
 		jas_eprintf("warning: ignoring BMP decoder options\n");
 	}
@@ -121,7 +124,8 @@
 	/* Read the bitmap header. */
 	if (bmp_gethdr(in, &hdr)) {
 		jas_eprintf("cannot get header\n");
-		return 0;
+		goto error;
+		//return 0;
 	}
 	JAS_DBGLOG(1, (
 	  "BMP header: magic 0x%x; siz %d; res1 %d; res2 %d; off %d\n",
@@ -131,33 +135,46 @@
 	/* Read the bitmap information. */
 	if (!(info = bmp_getinfo(in))) {
 		jas_eprintf("cannot get info\n");
-		return 0;
+		//return 0;
+		goto error;
 	}
 	JAS_DBGLOG(1,
-	  ("BMP information: len %d; width %d; height %d; numplanes %d; "
-	  "depth %d; enctype %d; siz %d; hres %d; vres %d; numcolors %d; "
-	  "mincolors %d\n", info->len, info->width, info->height, info->numplanes,
-	  info->depth, info->enctype, info->siz, info->hres, info->vres,
-	  info->numcolors, info->mincolors));
+	  ("BMP information: len %ld; width %ld; height %ld; numplanes %d; "
+	  "depth %d; enctype %ld; siz %ld; hres %ld; vres %ld; numcolors %ld; "
+	  "mincolors %ld\n", JAS_CAST(long, info->len),
+	  JAS_CAST(long, info->width), JAS_CAST(long, info->height),
+	  JAS_CAST(long, info->numplanes), JAS_CAST(long, info->depth),
+	  JAS_CAST(long, info->enctype), JAS_CAST(long, info->siz),
+	  JAS_CAST(long, info->hres), JAS_CAST(long, info->vres),
+	  JAS_CAST(long, info->numcolors), JAS_CAST(long, info->mincolors)));
+
+	if (info->width < 0 || info->height < 0 || info->numplanes < 0 ||
+	  info->depth < 0 || info->siz < 0 || info->hres < 0 || info->vres < 0) {
+		jas_eprintf("corrupt bit stream\n");
+		goto error;
+	}
 
 	/* Ensure that we support this type of BMP file. */
 	if (!bmp_issupported(&hdr, info)) {
 		jas_eprintf("error: unsupported BMP encoding\n");
-		bmp_info_destroy(info);
-		return 0;
+		//bmp_info_destroy(info);
+		//return 0;
+		goto error;
 	}
 
 	/* Skip over any useless data between the end of the palette
 	  and start of the bitmap data. */
 	if ((n = hdr.off - (BMP_HDRLEN + BMP_INFOLEN + BMP_PALLEN(info))) < 0) {
 		jas_eprintf("error: possibly bad bitmap offset?\n");
-		return 0;
+		goto error;
+		//return 0;
 	}
 	if (n > 0) {
 		jas_eprintf("skipping unknown data in BMP file\n");
 		if (bmp_gobble(in, n)) {
-			bmp_info_destroy(info);
-			return 0;
+			//bmp_info_destroy(info);
+			//return 0;
+			goto error;
 		}
 	}
 
@@ -179,8 +196,9 @@
 	/* Create image object. */
 	if (!(image = jas_image_create(numcmpts, cmptparms,
 	  JAS_CLRSPC_UNKNOWN))) {
-		bmp_info_destroy(info);
-		return 0;
+		//bmp_info_destroy(info);
+		//return 0;
+		goto error;
 	}
 
 	if (numcmpts == 3) {
@@ -199,14 +217,24 @@
 
 	/* Read the bitmap data. */
 	if (bmp_getdata(in, info, image)) {
+		//bmp_info_destroy(info);
+		//jas_image_destroy(image);
+		//return 0;
+		goto error;
+	}
+
+	bmp_info_destroy(info);
+
+	return image;
+
+error:
+	if (info) {
 		bmp_info_destroy(info);
+	}
+	if (image) {
 		jas_image_destroy(image);
-		return 0;
-	}
-
-	bmp_info_destroy(info);
-
-	return image;
+	}
+	return 0;
 }
 
 int bmp_validate(jas_stream_t *in)
```
