# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 4854_1
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4854_1`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 227-267 of the vulnerable file.

	osibsJpegInterchangeFormat,
	osibsStrile,
	osibsEof
} OJPEGStateInBufferSource;

typedef enum {
	ososSoi,
	ososQTable0,ososQTable1,ososQTable2,ososQTable3,
	ososDcTable0,ososDcTable1,ososDcTable2,ososDcTable3,
	ososAcTable0,ososAcTable1,ososAcTable2,ososAcTable3,
	ososDri,
	ososSof,
	ososSos,
	ososCompressed,
	ososRst,
	ososEoi
} OJPEGStateOutState;

typedef struct {
	TIFF* tif;
	#ifndef LIBJPEG_ENCAP_EXTERNAL
	JMP_BUF exit_jmpbuf;
	#endif
	TIFFVGetMethod vgetparent;
	TIFFVSetMethod vsetparent;
	TIFFPrintMethod printdir;
	uint64 file_size;
	uint32 image_width;
	uint32 image_length;
	uint32 strile_width;
	uint32 strile_length;
	uint32 strile_length_total;
	uint8 samples_per_pixel;
	uint8 plane_sample_offset;
	uint8 samples_per_pixel_per_plane;
	uint64 jpeg_interchange_format;
	uint64 jpeg_interchange_format_length;
	uint8 jpeg_proc;
	uint8 subsamplingcorrect;
	uint8 subsamplingcorrect_done;
	uint8 subsampling_tag;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -244,6 +244,7 @@
 
 typedef struct {
 	TIFF* tif;
+        int decoder_ok;
 	#ifndef LIBJPEG_ENCAP_EXTERNAL
 	JMP_BUF exit_jmpbuf;
 	#endif
@@ -722,6 +723,7 @@
 		}
 		sp->write_curstrile++;
 	}
+	sp->decoder_ok = 1;
 	return(1);
 }
 
@@ -784,8 +786,14 @@
 static int
 OJPEGDecode(TIFF* tif, uint8* buf, tmsize_t cc, uint16 s)
 {
+        static const char module[]="OJPEGDecode";
 	OJPEGState* sp=(OJPEGState*)tif->tif_data;
 	(void)s;
+        if( !sp->decoder_ok )
+        {
+            TIFFErrorExt(tif->tif_clientdata,module,"Cannot decode: decoder not correctly initialized");
+            return 0;
+        }
 	if (sp->libjpeg_jpeg_query_style==0)
 	{
 		if (OJPEGDecodeRaw(tif,buf,cc)==0)
```
