# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5479_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5479_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 269-309 of the vulnerable file.


#ifdef __cplusplus
}
#endif

void t2p_read_tiff_init(T2P*, TIFF*);
int t2p_cmp_t2p_page(const void*, const void*);
void t2p_read_tiff_data(T2P*, TIFF*);
void t2p_read_tiff_size(T2P*, TIFF*);
void t2p_read_tiff_size_tile(T2P*, TIFF*, ttile_t);
int t2p_tile_is_right_edge(T2P_TILES, ttile_t);
int t2p_tile_is_bottom_edge(T2P_TILES, ttile_t);
int t2p_tile_is_edge(T2P_TILES, ttile_t);
int t2p_tile_is_corner_edge(T2P_TILES, ttile_t);
tsize_t t2p_readwrite_pdf_image(T2P*, TIFF*, TIFF*);
tsize_t t2p_readwrite_pdf_image_tile(T2P*, TIFF*, TIFF*, ttile_t);
#ifdef OJPEG_SUPPORT
int t2p_process_ojpeg_tables(T2P*, TIFF*);
#endif
#ifdef JPEG_SUPPORT
int t2p_process_jpeg_strip(unsigned char*, tsize_t*, unsigned char*, tsize_t*, tstrip_t, uint32);
#endif
void t2p_tile_collapse_left(tdata_t, tsize_t, uint32, uint32, uint32);
void t2p_write_advance_directory(T2P*, TIFF*);
tsize_t t2p_sample_planar_separate_to_contig(T2P*, unsigned char*, unsigned char*, tsize_t);
tsize_t t2p_sample_realize_palette(T2P*, unsigned char*);
tsize_t t2p_sample_abgr_to_rgb(tdata_t, uint32);
tsize_t t2p_sample_rgba_to_rgb(tdata_t, uint32);
tsize_t t2p_sample_rgbaa_to_rgb(tdata_t, uint32);
tsize_t t2p_sample_lab_signed_to_unsigned(tdata_t, uint32);
tsize_t t2p_write_pdf_header(T2P*, TIFF*);
tsize_t t2p_write_pdf_obj_start(uint32, TIFF*);
tsize_t t2p_write_pdf_obj_end(TIFF*);
tsize_t t2p_write_pdf_name(unsigned char*, TIFF*);
tsize_t t2p_write_pdf_string(char*, TIFF*);
tsize_t t2p_write_pdf_stream(tdata_t, tsize_t, TIFF*);
tsize_t t2p_write_pdf_stream_start(TIFF*);
tsize_t t2p_write_pdf_stream_end(TIFF*);
tsize_t t2p_write_pdf_stream_dict(tsize_t, uint32, TIFF*);
tsize_t t2p_write_pdf_stream_dict_start(TIFF*);
tsize_t t2p_write_pdf_stream_dict_end(TIFF*);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -286,7 +286,7 @@
 int t2p_process_ojpeg_tables(T2P*, TIFF*);
 #endif
 #ifdef JPEG_SUPPORT
-int t2p_process_jpeg_strip(unsigned char*, tsize_t*, unsigned char*, tsize_t*, tstrip_t, uint32);
+int t2p_process_jpeg_strip(unsigned char*, tsize_t*, unsigned char*, tsize_t, tsize_t*, tstrip_t, uint32);
 #endif
 void t2p_tile_collapse_left(tdata_t, tsize_t, uint32, uint32, uint32);
 void t2p_write_advance_directory(T2P*, TIFF*);
@@ -2408,7 +2408,8 @@
 				if(!t2p_process_jpeg_strip(
 					stripbuffer, 
 					&striplength, 
-					buffer, 
+					buffer,
+                    t2p->tiff_datasize,
 					&bufferoffset, 
 					i, 
 					t2p->tiff_length)){
@@ -3439,6 +3440,7 @@
 	unsigned char* strip, 
 	tsize_t* striplength, 
 	unsigned char* buffer, 
+    tsize_t buffersize,
 	tsize_t* bufferoffset, 
 	tstrip_t no, 
 	uint32 height){
@@ -3473,6 +3475,8 @@
 		}
 		switch( strip[i] ){
 			case 0xd8:	/* SOI - start of image */
+                if( *bufferoffset + 2 > buffersize )
+                    return(0);
 				_TIFFmemcpy(&(buffer[*bufferoffset]), &(strip[i-1]), 2);
 				*bufferoffset+=2;
 				break;
@@ -3482,12 +3486,18 @@
 			case 0xc9:	/* SOF9 */
 			case 0xca:	/* SOF10 */
 				if(no==0){
+                    if( *bufferoffset + datalen + 2 + 6 > buffersize )
+                        return(0);
 					_TIFFmemcpy(&(buffer[*bufferoffset]), &(strip[i-1]), datalen+2);
+                    if( *bufferoffset + 9 >= buffersize )
+                        return(0);
 					ncomp = buffer[*bufferoffset+9];
 					if (ncomp < 1 || ncomp > 4)
 						return(0);
 					v_samp=1;
 					h_samp=1;
+                    if( *bufferoffset + 11 + 3*(ncomp-1) >= buffersize )
+                        return(0);
 					for(j=0;j<ncomp;j++){
 						uint16 samp = buffer[*bufferoffset+11+(3*j)];
 						if( (samp>>4) > h_samp) 
@@ -3519,20 +3529,28 @@
 				break;
 			case 0xc4: /* DHT */
 			case 0xdb: /* DQT */
+                if( *bufferoffset + datalen + 2 > buffersize )
+                    return(0);
 				_TIFFmemcpy(&(buffer[*bufferoffset]), &(strip[i-1]), datalen+2);
 				*bufferoffset+=datalen+2;
 				break;
 			case 0xda: /* SOS */
 				if(no==0){
+                    if( *bufferoffset + datalen + 2 > buffersize )
+                        return(0);
 					_TIFFmemcpy(&(buffer[*bufferoffset]), &(strip[i-1]), datalen+2);
 					*bufferoffset+=datalen+2;
 				} else {
+                    if( *bufferoffset + 2 > buffersize )
+                        return(0);
 					buffer[(*bufferoffset)++]=0xff;
 					buffer[(*bufferoffset)++]=
                                             (unsigned char)(0xd0 | ((no-1)%8));
 				}
 				i += datalen + 1;
 				/* copy remainder of strip */
+                if( *bufferoffset + *striplength - i > buffersize )
+                    return(0);
 				_TIFFmemcpy(&(buffer[*bufferoffset]), &(strip[i]), *striplength - i);
 				*bufferoffset+= *striplength - i;
 				return(1);
```
