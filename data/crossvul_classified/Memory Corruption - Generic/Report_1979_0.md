# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 1979_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1979_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 39-79 of the vulnerable file.

	Error error;

	Vector<uint8_t> pixels;
	error = pixels.resize(p_pixel_size);
	if (error != OK) {
		return error;
	}

	uint8_t *pixels_w = pixels.ptrw();

	size_t compressed_pos = 0;
	size_t output_pos = 0;
	size_t c = 0;
	size_t count = 0;

	while (output_pos < p_output_size) {
		c = p_compressed_buffer[compressed_pos];
		compressed_pos += 1;
		count = (c & 0x7f) + 1;

		if (c & 0x80) {
			for (size_t i = 0; i < p_pixel_size; i++) {
				pixels_w[i] = p_compressed_buffer[compressed_pos];
				compressed_pos += 1;
			}
			for (size_t i = 0; i < count; i++) {
				for (size_t j = 0; j < p_pixel_size; j++) {
					p_uncompressed_buffer[output_pos + j] = pixels_w[j];
				}
				output_pos += p_pixel_size;
			}
		} else {
			count *= p_pixel_size;
			for (size_t i = 0; i < count; i++) {
				p_uncompressed_buffer[output_pos] = p_compressed_buffer[compressed_pos];
				compressed_pos += 1;
				output_pos += 1;
			}
		}
	}
	return OK;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,10 @@
 		compressed_pos += 1;
 		count = (c & 0x7f) + 1;
 
+		if (output_pos + count * p_pixel_size > output_pos) {
+			return ERR_PARSE_ERROR;
+		}
+
 		if (c & 0x80) {
 			for (size_t i = 0; i < p_pixel_size; i++) {
 				pixels_w[i] = p_compressed_buffer[compressed_pos];
@@ -79,7 +83,7 @@
 	return OK;
 }
 
-Error ImageLoaderTGA::convert_to_image(Ref<Image> p_image, const uint8_t *p_buffer, const tga_header_s &p_header, const uint8_t *p_palette, const bool p_is_monochrome) {
+Error ImageLoaderTGA::convert_to_image(Ref<Image> p_image, const uint8_t *p_buffer, const tga_header_s &p_header, const uint8_t *p_palette, const bool p_is_monochrome, size_t p_output_size) {
 #define TGA_PUT_PIXEL(r, g, b, a)             \
 	int image_data_ofs = ((y * width) + x);   \
 	image_data_w[image_data_ofs * 4 + 0] = r; \
@@ -130,6 +134,9 @@
 		if (p_is_monochrome) {
 			while (y != y_end) {
 				while (x != x_end) {
+					if (i > p_output_size) {
+						return ERR_PARSE_ERROR;
+					}
 					uint8_t shade = p_buffer[i];
 
 					TGA_PUT_PIXEL(shade, shade, shade, 0xff)
@@ -143,6 +150,9 @@
 		} else {
 			while (y != y_end) {
 				while (x != x_end) {
+					if (i > p_output_size) {
+						return ERR_PARSE_ERROR;
+					}
 					uint8_t index = p_buffer[i];
 					uint8_t r = 0x00;
 					uint8_t g = 0x00;
@@ -171,6 +181,10 @@
 	} else if (p_header.pixel_depth == 24) {
 		while (y != y_end) {
 			while (x != x_end) {
+				if (i + 2 > p_output_size) {
+					return ERR_PARSE_ERROR;
+				}
+
 				uint8_t r = p_buffer[i + 2];
 				uint8_t g = p_buffer[i + 1];
 				uint8_t b = p_buffer[i + 0];
@@ -186,6 +200,10 @@
 	} else if (p_header.pixel_depth == 32) {
 		while (y != y_end) {
 			while (x != x_end) {
+				if (i + 3 > p_output_size) {
+					return ERR_PARSE_ERROR;
+				}
+
 				uint8_t a = p_buffer[i + 3];
 				uint8_t r = p_buffer[i + 2];
 				uint8_t g = p_buffer[i + 1];
@@ -279,7 +297,7 @@
 		const uint8_t *src_image_r = src_image.ptr();
 
 		const size_t pixel_size = tga_header.pixel_depth >> 3;
-		const size_t buffer_size = (tga_header.image_width * tga_header.image_height) * pixel_size;
+		size_t buffer_size = (tga_header.image_width * tga_header.image_height) * pixel_size;
 
 		Vector<uint8_t> uncompressed_buffer;
 		uncompressed_buffer.resize(buffer_size);
@@ -297,11 +315,12 @@
 			}
 		} else {
 			buffer = src_image_r;
+			buffer_size = src_image_len;
 		};
 
 		if (err == OK) {
 			const uint8_t *palette_r = palette.ptr();
-			err = convert_to_image(p_image, buffer, tga_header, palette_r, is_monochrome);
+			err = convert_to_image(p_image, buffer, tga_header, palette_r, is_monochrome, buffer_size);
 		}
 	}
 
```
