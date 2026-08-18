# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5102_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5102_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 442-482 of the vulnerable file.

	    }
	} else {
	    REPEAT(stride, *op = ToLinear8[*wp&mask]; wp++; op++)
	    n -= stride;
	    while (n > 0) {
		REPEAT(stride,
		    wp[stride] += *wp; *op = ToLinear8[*wp&mask]; wp++; op++)
		n -= stride;
	    }
	}
    }
}

/*
 * State block for each open TIFF
 * file using PixarLog compression/decompression.
 */
typedef	struct {
	TIFFPredictorState	predict;
	z_stream		stream;
	uint16			*tbuf; 
	uint16			stride;
	int			state;
	int			user_datafmt;
	int			quality;
#define PLSTATE_INIT 1

	TIFFVSetMethod		vgetparent;	/* super-class method */
	TIFFVSetMethod		vsetparent;	/* super-class method */

	float *ToLinearF;
	uint16 *ToLinear16;
	unsigned char *ToLinear8;
	uint16  *FromLT2;
	uint16  *From14; /* Really for 16-bit data, but we shift down 2 */
	uint16  *From8;
	
} PixarLogState;

static int
PixarLogMakeTables(PixarLogState *sp)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -459,6 +459,7 @@
 typedef	struct {
 	TIFFPredictorState	predict;
 	z_stream		stream;
+	tmsize_t		tbuf_size; /* only set/used on reading for now */
 	uint16			*tbuf; 
 	uint16			stride;
 	int			state;
@@ -694,6 +695,7 @@
 	sp->tbuf = (uint16 *) _TIFFmalloc(tbuf_size);
 	if (sp->tbuf == NULL)
 		return (0);
+	sp->tbuf_size = tbuf_size;
 	if (sp->user_datafmt == PIXARLOGDATAFMT_UNKNOWN)
 		sp->user_datafmt = PixarLogGuessDataFmt(td);
 	if (sp->user_datafmt == PIXARLOGDATAFMT_UNKNOWN) {
@@ -781,6 +783,12 @@
 	if (sp->stream.avail_out != nsamples * sizeof(uint16))
 	{
 		TIFFErrorExt(tif->tif_clientdata, module, "ZLib cannot deal with buffers this size");
+		return (0);
+	}
+	/* Check that we will not fill more than what was allocated */
+	if (sp->stream.avail_out > sp->tbuf_size)
+	{
+		TIFFErrorExt(tif->tif_clientdata, module, "sp->stream.avail_out > sp->tbuf_size");
 		return (0);
 	}
 	do {
```
