# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4856_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4856_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 141-181 of the vulnerable file.

 *  SGILOGENCODE_NODITHER     = do not dither encoded values
 *  SGILOGENCODE_RANDITHER    = apply random dithering during encoding
 *
 * The default value of this tag is SGILOGENCODE_NODITHER for
 * COMPRESSION_SGILOG to maximize run-length encoding and
 * SGILOGENCODE_RANDITHER for COMPRESSION_SGILOG24 to turn
 * quantization errors into noise.
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

/*
 * State block for each open TIFF
 * file using LogLuv compression/decompression.
 */
typedef struct logLuvState LogLuvState;

struct logLuvState {
	int                     user_datafmt;   /* user data format */
	int                     encode_meth;    /* encoding method */
	int                     pixel_size;     /* bytes per pixel */

	uint8*                  tbuf;           /* translation buffer */
	tmsize_t                tbuflen;        /* buffer length */
	void (*tfunc)(LogLuvState*, uint8*, tmsize_t);

	TIFFVSetMethod          vgetparent;     /* super-class method */
	TIFFVSetMethod          vsetparent;     /* super-class method */
};

#define DecoderState(tif)	((LogLuvState*) (tif)->tif_data)
#define EncoderState(tif)	((LogLuvState*) (tif)->tif_data)

#define SGILOGDATAFMT_UNKNOWN -1

#define MINRUN 4 /* minimum run length */

/*
 * Decode a string of 16-bit gray pixels.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,6 +158,7 @@
 typedef struct logLuvState LogLuvState;
 
 struct logLuvState {
+        int                     encoder_state;  /* 1 if encoder correctly initialized */
 	int                     user_datafmt;   /* user data format */
 	int                     encode_meth;    /* encoding method */
 	int                     pixel_size;     /* bytes per pixel */
@@ -1552,6 +1553,7 @@
 		    td->td_photometric, "must be either LogLUV or LogL");
 		break;
 	}
+	sp->encoder_state = 1;
 	return (1);
 notsupported:
 	TIFFErrorExt(tif->tif_clientdata, module,
@@ -1563,19 +1565,27 @@
 static void
 LogLuvClose(TIFF* tif)
 {
+        LogLuvState* sp = (LogLuvState*) tif->tif_data;
 	TIFFDirectory *td = &tif->tif_dir;
 
+	assert(sp != 0);
 	/*
 	 * For consistency, we always want to write out the same
 	 * bitspersample and sampleformat for our TIFF file,
 	 * regardless of the data format being used by the application.
 	 * Since this routine is called after tags have been set but
 	 * before they have been recorded in the file, we reset them here.
+         * Note: this is really a nasty approach. See PixarLogClose
 	 */
-	td->td_samplesperpixel =
-	    (td->td_photometric == PHOTOMETRIC_LOGL) ? 1 : 3;
-	td->td_bitspersample = 16;
-	td->td_sampleformat = SAMPLEFORMAT_INT;
+        if( sp->encoder_state )
+        {
+            /* See PixarLogClose. Might avoid issues with tags whose size depends
+             * on those below, but not completely sure this is enough. */
+            td->td_samplesperpixel =
+                (td->td_photometric == PHOTOMETRIC_LOGL) ? 1 : 3;
+            td->td_bitspersample = 16;
+            td->td_sampleformat = SAMPLEFORMAT_INT;
+        }
 }
 
 static void
```
