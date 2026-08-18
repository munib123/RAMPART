# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5162_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5162_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 227-272 of the vulnerable file.

#endif

#if PNG_LIBPNG_VER >= 10500 && defined(PNG_UNKNOWN_CHUNKS_SUPPORTED)
    /* copy standard chunks too */
    png_set_keep_unknown_chunks(png_ptr, PNG_HANDLE_CHUNK_IF_SAFE, (png_const_bytep)"pHYs\0iTXt\0tEXt\0zTXt", 4);
#endif
    png_set_read_user_chunk_fn(png_ptr, &mainprog_ptr->chunks, read_chunk_callback);

    struct rwpng_read_data read_data = {infile, 0};
    png_set_read_fn(png_ptr, &read_data, user_read_data);

    png_read_info(png_ptr, info_ptr);  /* read all PNG info up to image data */

    /* alternatively, could make separate calls to png_get_image_width(),
     * etc., but want bit_depth and color_type for later [don't care about
     * compression_type and filter_type => NULLs] */

    png_get_IHDR(png_ptr, info_ptr, &mainprog_ptr->width, &mainprog_ptr->height,
                 &bit_depth, &color_type, NULL, NULL, NULL);

    // For overflow safety reject images that won't fit in 32-bit
    if (mainprog_ptr->width > INT_MAX/mainprog_ptr->height) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return PNG_OUT_OF_MEMORY_ERROR;  /* not quite true, but whatever */
    }

    /* expand palette images to RGB, low-bit-depth grayscale images to 8 bits,
     * transparency chunks to full alpha channel; strip 16-bit-per-sample
     * images to 8 bits per sample; and convert grayscale to RGB[A] */

    /* GRR TO DO:  preserve all safe-to-copy ancillary PNG chunks */

    if (!(color_type & PNG_COLOR_MASK_ALPHA)) {
#ifdef PNG_READ_FILLER_SUPPORTED
        png_set_expand(png_ptr);
        png_set_filler(png_ptr, 65535L, PNG_FILLER_AFTER);
#else
        fprintf(stderr, "pngquant readpng:  image is neither RGBA nor GA\n");
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        mainprog_ptr->retval = WRONG_INPUT_COLOR_TYPE;
        return mainprog_ptr->retval;
#endif
    }

    if (bit_depth == 16) {
        png_set_strip_16(png_ptr);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -243,12 +243,6 @@
 
     png_get_IHDR(png_ptr, info_ptr, &mainprog_ptr->width, &mainprog_ptr->height,
                  &bit_depth, &color_type, NULL, NULL, NULL);
-
-    // For overflow safety reject images that won't fit in 32-bit
-    if (mainprog_ptr->width > INT_MAX/mainprog_ptr->height) {
-        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
-        return PNG_OUT_OF_MEMORY_ERROR;  /* not quite true, but whatever */
-    }
 
     /* expand palette images to RGB, low-bit-depth grayscale images to 8 bits,
      * transparency chunks to full alpha channel; strip 16-bit-per-sample
@@ -304,6 +298,12 @@
 
     rowbytes = png_get_rowbytes(png_ptr, info_ptr);
 
+    // For overflow safety reject images that won't fit in 32-bit
+    if (rowbytes > INT_MAX/mainprog_ptr->height) {
+        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
+        return PNG_OUT_OF_MEMORY_ERROR;
+    }
+
     if ((mainprog_ptr->rgba_data = malloc(rowbytes * mainprog_ptr->height)) == NULL) {
         fprintf(stderr, "pngquant readpng:  unable to allocate image data\n");
         png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
```
