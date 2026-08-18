# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5240_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5240_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 283-323 of the vulnerable file.

			gdFree(conversion_buffer);
			gdFree(decompression_buffer);
			return -1;
		}

		buffer_caret = 0;

		while( buffer_caret < rle_size) {
			decompression_buffer[buffer_caret] = (int)conversion_buffer[buffer_caret];
			buffer_caret++;
		}

		buffer_caret = 0;

		while( bitmap_caret < image_block_size ) {
			
			if ((decompression_buffer[buffer_caret] & TGA_RLE_FLAG) == TGA_RLE_FLAG) {
				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & ~TGA_RLE_FLAG ) + 1 );
				buffer_caret++;

				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
					gdFree( decompression_buffer );
					gdFree( conversion_buffer );
					return -1;
				}

				for (i = 0; i < encoded_pixels; i++) {
					memcpy(tga->bitmap + bitmap_caret, decompression_buffer + buffer_caret, pixel_block_size * sizeof(int));
					bitmap_caret += pixel_block_size;
				}
				buffer_caret += pixel_block_size;

			} else {
				encoded_pixels = decompression_buffer[ buffer_caret ] + 1;
				buffer_caret++;

				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
					gdFree( decompression_buffer );
					gdFree( conversion_buffer );
					return -1;
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -300,7 +300,8 @@
 				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & ~TGA_RLE_FLAG ) + 1 );
 				buffer_caret++;
 
-				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size
+						|| buffer_caret + pixel_block_size > rle_size) {
 					gdFree( decompression_buffer );
 					gdFree( conversion_buffer );
 					return -1;
@@ -316,7 +317,8 @@
 				encoded_pixels = decompression_buffer[ buffer_caret ] + 1;
 				buffer_caret++;
 
-				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size
+						|| buffer_caret + (encoded_pixels * pixel_block_size) > rle_size) {
 					gdFree( decompression_buffer );
 					gdFree( conversion_buffer );
 					return -1;
```
