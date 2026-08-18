# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 4800_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4800_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 2878-2918 of the vulnerable file.

			t2pWriteFile(output, (tdata_t) buffer, bufferoffset);
			_TIFFfree(buffer);
			return(bufferoffset);
		}
#endif
#ifdef JPEG_SUPPORT
		if(t2p->tiff_compression == COMPRESSION_JPEG){
			unsigned char table_end[2];
			uint32 count = 0;
			buffer= (unsigned char*) _TIFFmalloc(t2p->tiff_datasize);
			if(buffer==NULL){
				TIFFError(TIFF2PDF_MODULE, 
					"Can't allocate " TIFF_SIZE_FORMAT " bytes of memory "
                                        "for t2p_readwrite_pdf_image_tile, %s", 
                                          (TIFF_SIZE_T) t2p->tiff_datasize, 
					TIFFFileName(input));
				t2p->t2p_error = T2P_ERR_ERROR;
				return(0);
			}
			if(TIFFGetField(input, TIFFTAG_JPEGTABLES, &count, &jpt) != 0) {
				if (count >= 4) {
                                        int retTIFFReadRawTile;
                    /* Ignore EOI marker of JpegTables */
					_TIFFmemcpy(buffer, jpt, count - 2);
					bufferoffset += count - 2;
                    /* Store last 2 bytes of the JpegTables */
					table_end[0] = buffer[bufferoffset-2];
					table_end[1] = buffer[bufferoffset-1];
					xuint32 = bufferoffset;
                                        bufferoffset -= 2;
                                        retTIFFReadRawTile= TIFFReadRawTile(
						input, 
						tile, 
						(tdata_t) &(((unsigned char*)buffer)[bufferoffset]), 
						-1);
                                        if( retTIFFReadRawTile < 0 )
                                        {
                                            _TIFFfree(buffer);
                                            t2p->t2p_error = T2P_ERR_ERROR;
                                            return(0);
                                        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2895,7 +2895,7 @@
 				return(0);
 			}
 			if(TIFFGetField(input, TIFFTAG_JPEGTABLES, &count, &jpt) != 0) {
-				if (count >= 4) {
+				if (count > 4) {
                                         int retTIFFReadRawTile;
                     /* Ignore EOI marker of JpegTables */
 					_TIFFmemcpy(buffer, jpt, count - 2);
```
