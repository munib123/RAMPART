# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5237_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5237_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 179-219 of the vulnerable file.

	}

	return 1;
}

/*!	\brief Reads a TGA image data into buffer.
 *	Reads the image data block from a binary TGA file populating the referenced TGA structure.
 *	\param ctx Pointer to TGA binary file
 *	\param tga Pointer to TGA structure
 *	\return int 0 on sucess, -1 on failure
 */
int read_image_tga( gdIOCtx *ctx, oTga *tga )
{
	int pixel_block_size = (tga->bits / 8);
	int image_block_size = (tga->width * tga->height) * pixel_block_size;
	uint8_t* decompression_buffer = NULL;
	unsigned char* conversion_buffer = NULL;
	int buffer_caret = 0;
	int bitmap_caret = 0;
	int i = 0;
	int j = 0;
	uint8_t encoded_pixels;

	if(overflow2(tga->width, tga->height)) {
		return -1;
	}

	if(overflow2(tga->width * tga->height, pixel_block_size)) {
		return -1;
	}

	if(overflow2(image_block_size, sizeof(int))) {
		return -1;
	}

	/*! \todo Add more image type support.
	 */
	if (tga->imagetype != TGA_TYPE_RGB && tga->imagetype != TGA_TYPE_RGB_RLE)
		return -1;

	/*!	\brief Allocate memmory for image block
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -196,7 +196,6 @@
 	int buffer_caret = 0;
 	int bitmap_caret = 0;
 	int i = 0;
-	int j = 0;
 	uint8_t encoded_pixels;
 
 	if(overflow2(tga->width, tga->height)) {
@@ -280,43 +279,34 @@
 		while( bitmap_caret < image_block_size ) {
 			
 			if ((decompression_buffer[buffer_caret] & TGA_RLE_FLAG) == TGA_RLE_FLAG) {
-				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & 127 ) + 1 );
+				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & !TGA_RLE_FLAG ) + 1 );
 				buffer_caret++;
 
-				if (encoded_pixels != 0) {
-				
-					if (!((buffer_caret + (encoded_pixels * pixel_block_size)) < image_block_size)) {
-						gdFree( decompression_buffer );
-						gdFree( conversion_buffer );
-						return -1;
-					}
-
-					for (i = 0; i < encoded_pixels; i++) {
-						for (j = 0; j < pixel_block_size; j++, bitmap_caret++) {
-							tga->bitmap[ bitmap_caret ] = decompression_buffer[ buffer_caret + j ];
-						}
-					}
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) >= image_block_size) {
+					gdFree( decompression_buffer );
+					gdFree( conversion_buffer );
+					return -1;
+				}
+
+				for (i = 0; i < encoded_pixels; i++) {
+					memcpy(tga->bitmap + bitmap_caret, decompression_buffer + buffer_caret, pixel_block_size);
+					bitmap_caret += pixel_block_size;
 				}
 				buffer_caret += pixel_block_size;
+
 			} else {
 				encoded_pixels = decompression_buffer[ buffer_caret ] + 1;
 				buffer_caret++;
 
-				if (encoded_pixels != 0) {
-				
-					if (!((buffer_caret + (encoded_pixels * pixel_block_size)) < image_block_size)) {
-						gdFree( decompression_buffer );
-						gdFree( conversion_buffer );
-						return -1;
-					}
-
-					for (i = 0; i < encoded_pixels; i++) {
-						for( j = 0; j < pixel_block_size; j++, bitmap_caret++ ) {
-							tga->bitmap[ bitmap_caret ] = decompression_buffer[ buffer_caret + j ];
-						}
-						buffer_caret += pixel_block_size;
-					}
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) >= image_block_size) {
+					gdFree( decompression_buffer );
+					gdFree( conversion_buffer );
+					return -1;
 				}
+
+				memcpy(tga->bitmap + bitmap_caret, decompression_buffer + buffer_caret, encoded_pixels * pixel_block_size);
+				bitmap_caret += (encoded_pixels * pixel_block_size);
+				buffer_caret += (encoded_pixels * pixel_block_size);
 			}
 		}
 		gdFree( decompression_buffer );
```
