# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5418_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5418_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 71-111 of the vulnerable file.


#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <float.h>
#include <assert.h>
#include <stdint.h>

#include <jasper/jasper.h>

/******************************************************************************\
*
\******************************************************************************/

typedef enum {
	OPT_HELP,
	OPT_VERSION,
	OPT_VERBOSE,
	OPT_INFILE,
	OPT_DEBUG,
	OPT_MAXMEM
} optid_t;

/******************************************************************************\
*
\******************************************************************************/

static void usage(void);
static void cmdinfo(void);

/******************************************************************************\
*
\******************************************************************************/

static jas_opt_t opts[] = {
	{OPT_HELP, "help", 0},
	{OPT_VERSION, "version", 0},
	{OPT_VERBOSE, "verbose", 0},
	{OPT_INFILE, "f", JAS_OPT_HASARG},
	{OPT_DEBUG, "debug-level", JAS_OPT_HASARG},
#if defined(JAS_DEFAULT_MAX_MEM_USAGE)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,6 +88,7 @@
 	OPT_VERBOSE,
 	OPT_INFILE,
 	OPT_DEBUG,
+	OPT_MAXSAMPLES,
 	OPT_MAXMEM
 } optid_t;
 
@@ -108,6 +109,7 @@
 	{OPT_VERBOSE, "verbose", 0},
 	{OPT_INFILE, "f", JAS_OPT_HASARG},
 	{OPT_DEBUG, "debug-level", JAS_OPT_HASARG},
+	{OPT_MAXSAMPLES, "max-samples", JAS_OPT_HASARG},
 #if defined(JAS_DEFAULT_MAX_MEM_USAGE)
 	{OPT_MAXMEM, "memory-limit", JAS_OPT_HASARG},
 #endif
@@ -135,6 +137,8 @@
 	char *fmtname;
 	int debug;
 	size_t max_mem;
+	size_t max_samples;
+	char optstr[32];
 
 	if (jas_init()) {
 		abort();
@@ -142,6 +146,7 @@
 
 	cmdname = argv[0];
 
+	max_samples = 64 * JAS_MEBI;
 	infile = 0;
 	verbose = 0;
 	debug = 0;
@@ -164,6 +169,9 @@
 			break;
 		case OPT_INFILE:
 			infile = jas_optarg;
+			break;
+		case OPT_MAXSAMPLES:
+			max_samples = strtoull(jas_optarg, 0, 10);
 			break;
 		case OPT_MAXMEM:
 			max_mem = strtoull(jas_optarg, 0, 10);
@@ -199,8 +207,10 @@
 		fprintf(stderr, "unknown image format\n");
 	}
 
+	snprintf(optstr, sizeof(optstr), "max_samples=%-zu", max_samples);
+
 	/* Decode the image. */
-	if (!(image = jas_image_decode(instream, fmtid, 0))) {
+	if (!(image = jas_image_decode(instream, fmtid, optstr))) {
 		jas_stream_close(instream);
 		fprintf(stderr, "cannot load image\n");
 		return EXIT_FAILURE;
@@ -208,6 +218,11 @@
 
 	/* Close the image file. */
 	jas_stream_close(instream);
+
+	if (!(fmtname = jas_image_fmttostr(fmtid))) {
+		jas_eprintf("format name lookup failed\n");
+		return EXIT_FAILURE;
+	}
 
 	if (!(numcmpts = jas_image_numcmpts(image))) {
 		fprintf(stderr, "warning: image has no components\n");
@@ -221,10 +236,8 @@
 		height = 0;
 		depth = 0;
 	}
-	if (!(fmtname = jas_image_fmttostr(fmtid))) {
-		abort();
-	}
-	printf("%s %d %d %d %d %ld\n", fmtname, numcmpts, width, height, depth, (long) jas_image_rawsize(image));
+	printf("%s %d %d %d %d %ld\n", fmtname, numcmpts, width, height, depth,
+	  JAS_CAST(long, jas_image_rawsize(image)));
 
 	jas_image_destroy(image);
 	jas_image_clearfmts();
```
