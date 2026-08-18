# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5363_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5363_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 68-108 of the vulnerable file.

/******************************************************************************\
* Includes.
\******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <float.h>
#include <assert.h>

#include <jasper/jasper.h>

/******************************************************************************\
*
\******************************************************************************/

typedef enum {
	OPT_HELP,
	OPT_VERSION,
	OPT_VERBOSE,
	OPT_INFILE
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
	{-1, 0, 0}
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,7 +85,8 @@
 	OPT_HELP,
 	OPT_VERSION,
 	OPT_VERBOSE,
-	OPT_INFILE
+	OPT_INFILE,
+	OPT_DEBUG
 } optid_t;
 
 /******************************************************************************\
@@ -104,6 +105,7 @@
 	{OPT_VERSION, "version", 0},
 	{OPT_VERBOSE, "verbose", 0},
 	{OPT_INFILE, "f", JAS_OPT_HASARG},
+	{OPT_DEBUG, "debug-level", JAS_OPT_HASARG},
 	{-1, 0, 0}
 };
 
@@ -126,6 +128,7 @@
 	int numcmpts;
 	int verbose;
 	char *fmtname;
+	int debug;
 
 	if (jas_init()) {
 		abort();
@@ -135,6 +138,7 @@
 
 	infile = 0;
 	verbose = 0;
+	debug = 0;
 
 	/* Parse the command line options. */
 	while ((id = jas_getopt(argc, argv, opts)) >= 0) {
@@ -146,6 +150,9 @@
 			printf("%s\n", JAS_VERSION);
 			exit(EXIT_SUCCESS);
 			break;
+		case OPT_DEBUG:
+			debug = atoi(jas_optarg);
+			break;
 		case OPT_INFILE:
 			infile = jas_optarg;
 			break;
@@ -155,6 +162,8 @@
 			break;
 		}
 	}
+
+	jas_setdbglevel(debug);
 
 	/* Open the image file. */
 	if (infile) {
@@ -177,6 +186,7 @@
 
 	/* Decode the image. */
 	if (!(image = jas_image_decode(instream, fmtid, 0))) {
+		jas_stream_close(instream);
 		fprintf(stderr, "cannot load image\n");
 		return EXIT_FAILURE;
 	}
```
