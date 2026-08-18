# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5238_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5238_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 261-301 of the vulnerable file.

			gdFree( decompression_buffer );
			return -1;
		}

		if (gdGetBuf(conversion_buffer, image_block_size, ctx) != image_block_size) {
			gdFree(conversion_buffer);
			gdFree(decompression_buffer);
			return -1;
		}

		buffer_caret = 0;

		while( buffer_caret < image_block_size) {
			decompression_buffer[buffer_caret] = (int)conversion_buffer[buffer_caret];
			buffer_caret++;
		}

		buffer_caret = 0;

		while( bitmap_caret < image_block_size ) {

			if ((decompression_buffer[buffer_caret] & TGA_RLE_FLAG) == TGA_RLE_FLAG) {
				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & 127 ) + 1 );
				buffer_caret++;

				for (i = 0; i < encoded_pixels; i++) {
					for (j = 0; j < pixel_block_size; j++, bitmap_caret++) {
						tga->bitmap[ bitmap_caret ] = decompression_buffer[ buffer_caret + j ];
					}
				}
				buffer_caret += pixel_block_size;
			} else {
				encoded_pixels = decompression_buffer[ buffer_caret ] + 1;
				buffer_caret++;

				for (i = 0; i < encoded_pixels; i++) {
					for( j = 0; j < pixel_block_size; j++, bitmap_caret++ ) {
						tga->bitmap[ bitmap_caret ] = decompression_buffer[ buffer_caret + j ];
					}
					buffer_caret += pixel_block_size;
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -278,14 +278,23 @@
 		buffer_caret = 0;
 
 		while( bitmap_caret < image_block_size ) {
-
+			
 			if ((decompression_buffer[buffer_caret] & TGA_RLE_FLAG) == TGA_RLE_FLAG) {
 				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & 127 ) + 1 );
 				buffer_caret++;
 
-				for (i = 0; i < encoded_pixels; i++) {
-					for (j = 0; j < pixel_block_size; j++, bitmap_caret++) {
-						tga->bitmap[ bitmap_caret ] = decompression_buffer[ buffer_caret + j ];
+				if (encoded_pixels != 0) {
+				
+					if (!((buffer_caret + (encoded_pixels * pixel_block_size)) < image_block_size)) {
+						gdFree( decompression_buffer );
+						gdFree( conversion_buffer );
+						return -1;
+					}
+
+					for (i = 0; i < encoded_pixels; i++) {
+						for (j = 0; j < pixel_block_size; j++, bitmap_caret++) {
+							tga->bitmap[ bitmap_caret ] = decompression_buffer[ buffer_caret + j ];
+						}
 					}
 				}
 				buffer_caret += pixel_block_size;
@@ -293,11 +302,20 @@
 				encoded_pixels = decompression_buffer[ buffer_caret ] + 1;
 				buffer_caret++;
 
-				for (i = 0; i < encoded_pixels; i++) {
-					for( j = 0; j < pixel_block_size; j++, bitmap_caret++ ) {
-						tga->bitmap[ bitmap_caret ] = decompression_buffer[ buffer_caret + j ];
+				if (encoded_pixels != 0) {
+				
+					if (!((buffer_caret + (encoded_pixels * pixel_block_size)) < image_block_size)) {
+						gdFree( decompression_buffer );
+						gdFree( conversion_buffer );
+						return -1;
 					}
-					buffer_caret += pixel_block_size;
+
+					for (i = 0; i < encoded_pixels; i++) {
+						for( j = 0; j < pixel_block_size; j++, bitmap_caret++ ) {
+							tga->bitmap[ bitmap_caret ] = decompression_buffer[ buffer_caret + j ];
+						}
+						buffer_caret += pixel_block_size;
+					}
 				}
 			}
 		}
```
