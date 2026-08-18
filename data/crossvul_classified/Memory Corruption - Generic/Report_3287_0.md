# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3287_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3287_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 51-91 of the vulnerable file.

} PFLAC_PCM ;

typedef struct
{
	FLAC__StreamDecoder *fsd ;
	FLAC__StreamEncoder *fse ;

	PFLAC_PCM pcmtype ;
	void* ptr ;
	unsigned pos, len, remain ;

	FLAC__StreamMetadata *metadata ;

	const int32_t * const * wbuffer ;
	int32_t * rbuffer [FLAC__MAX_CHANNELS] ;

	int32_t* encbuffer ;
	unsigned bufferpos ;

	const FLAC__Frame *frame ;
	FLAC__bool bufferbackup ;

	unsigned compression ;
} FLAC_PRIVATE ;

typedef struct
{	const char *tag ;
	int type ;
} FLAC_TAG ;

static sf_count_t	flac_seek (SF_PRIVATE *psf, int mode, sf_count_t offset) ;
static int			flac_byterate (SF_PRIVATE *psf) ;
static int			flac_close (SF_PRIVATE *psf) ;

static int			flac_enc_init (SF_PRIVATE *psf) ;
static int			flac_read_header (SF_PRIVATE *psf) ;

static sf_count_t	flac_read_flac2s (SF_PRIVATE *psf, short *ptr, sf_count_t len) ;
static sf_count_t	flac_read_flac2i (SF_PRIVATE *psf, int *ptr, sf_count_t len) ;
static sf_count_t	flac_read_flac2f (SF_PRIVATE *psf, float *ptr, sf_count_t len) ;
static sf_count_t	flac_read_flac2d (SF_PRIVATE *psf, double *ptr, sf_count_t len) ;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,9 +68,9 @@
 	unsigned bufferpos ;
 
 	const FLAC__Frame *frame ;
-	FLAC__bool bufferbackup ;
 
 	unsigned compression ;
+
 } FLAC_PRIVATE ;
 
 typedef struct
@@ -187,10 +187,9 @@
 
 	if (pflac->ptr == NULL)
 	{	/*
-		**	Not sure why this code is here and not elsewhere.
-		**	Removing it causes valgrind errors.
+		** This pointer is reset to NULL each time the current frame has been
+		** decoded. Somehow its used during encoding and decoding.
 		*/
-		pflac->bufferbackup = SF_TRUE ;
 		for (i = 0 ; i < channels ; i++)
 		{
 			if (pflac->rbuffer [i] == NULL)
@@ -205,6 +204,11 @@
 
 
 	len = SF_MIN (pflac->len, frame->header.blocksize) ;
+
+	if (pflac->remain % channels != 0)
+	{	psf_log_printf (psf, "Error: pflac->remain %u    channels %u\n", pflac->remain, channels) ;
+		return 0 ;
+		} ;
 
 	switch (pflac->pcmtype)
 	{	case PFLAC_PCM_SHORT :
@@ -381,7 +385,6 @@
 	pflac->frame = frame ;
 	pflac->bufferpos = 0 ;
 
-	pflac->bufferbackup = SF_FALSE ;
 	pflac->wbuffer = buffer ;
 
 	flac_buffer_copy (psf) ;
@@ -907,11 +910,19 @@
 static unsigned
 flac_read_loop (SF_PRIVATE *psf, unsigned len)
 {	FLAC_PRIVATE* pflac = (FLAC_PRIVATE*) psf->codec_data ;
+	FLAC__StreamDecoderState state ;
 
 	pflac->pos = 0 ;
 	pflac->len = len ;
 	pflac->remain = len ;
 
+	state = FLAC__stream_decoder_get_state (pflac->fsd) ;
+	if (state > FLAC__STREAM_DECODER_END_OF_STREAM)
+	{	psf_log_printf (psf, "FLAC__stream_decoder_get_state returned %s\n", FLAC__StreamDecoderStateString [state]) ;
+		/* Current frame is busted, so NULL the pointer. */
+		pflac->frame = NULL ;
+		} ;
+
 	/* First copy data that has already been decoded and buffered. */
 	if (pflac->frame != NULL && pflac->bufferpos < pflac->frame->header.blocksize)
 		flac_buffer_copy (psf) ;
@@ -920,8 +931,13 @@
 	while (pflac->pos < pflac->len)
 	{	if (FLAC__stream_decoder_process_single (pflac->fsd) == 0)
 			break ;
-		if (FLAC__stream_decoder_get_state (pflac->fsd) >= FLAC__STREAM_DECODER_END_OF_STREAM)
-			break ;
+		state = FLAC__stream_decoder_get_state (pflac->fsd) ;
+		if (state >= FLAC__STREAM_DECODER_END_OF_STREAM)
+		{	psf_log_printf (psf, "FLAC__stream_decoder_get_state returned %s\n", FLAC__StreamDecoderStateString [state]) ;
+			/* Current frame is busted, so NULL the pointer. */
+			pflac->frame = NULL ;
+			break ;
+			} ;
 		} ;
 
 	pflac->ptr = NULL ;
```
