# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4586_2
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4586_2`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 336-376 of the vulnerable file.

        int rv;
        uint32 ifdoffset = clientstate->ifd;
        TRACE(("reading tiff ifd %u\n", ifdoffset));
        rv = TIFFSetSubDirectory(tiff, ifdoffset);
        if (!rv){
            TRACE(("error in TIFFSetSubDirectory"));
            return -1;
        }
    }

    if (TIFFIsTiled(tiff)) {
        UINT32 x, y, tile_y, row_byte_size;
        UINT32 tile_width, tile_length, current_tile_width;
        UINT8 *new_data;

        TIFFGetField(tiff, TIFFTAG_TILEWIDTH, &tile_width);
        TIFFGetField(tiff, TIFFTAG_TILELENGTH, &tile_length);

        // We could use TIFFTileSize, but for YCbCr data it returns subsampled data size
        row_byte_size = (tile_width * state->bits + 7) / 8;
        state->bytes = row_byte_size * tile_length;

        /* overflow check for malloc */
        if (state->bytes > INT_MAX - 1) {
            state->errcode = IMAGING_CODEC_MEMORY;
            TIFFClose(tiff);
            return -1;
        }

        /* realloc to fit whole tile */
        new_data = realloc (state->buffer, state->bytes);
        if (!new_data) {
            state->errcode = IMAGING_CODEC_MEMORY;
            TIFFClose(tiff);
            return -1;
        }

        state->buffer = new_data;

        TRACE(("TIFFTileSize: %d\n", state->bytes));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -353,16 +353,18 @@
 
         // We could use TIFFTileSize, but for YCbCr data it returns subsampled data size
         row_byte_size = (tile_width * state->bits + 7) / 8;
-        state->bytes = row_byte_size * tile_length;
-
-        /* overflow check for malloc */
-        if (state->bytes > INT_MAX - 1) {
+
+        /* overflow check for realloc */
+        if (INT_MAX / row_byte_size < tile_length) {
             state->errcode = IMAGING_CODEC_MEMORY;
             TIFFClose(tiff);
             return -1;
         }
+        
+        state->bytes = row_byte_size * tile_length;
 
         /* realloc to fit whole tile */
+        /* malloc check above */
         new_data = realloc (state->buffer, state->bytes);
         if (!new_data) {
             state->errcode = IMAGING_CODEC_MEMORY;
@@ -415,11 +417,20 @@
 
         // We could use TIFFStripSize, but for YCbCr data it returns subsampled data size
         row_byte_size = (state->xsize * state->bits + 7) / 8;
+
+        /* overflow check for realloc */
+        if (INT_MAX / row_byte_size < rows_per_strip) {
+            state->errcode = IMAGING_CODEC_MEMORY;
+            TIFFClose(tiff);
+            return -1;
+        }
+        
         state->bytes = rows_per_strip * row_byte_size;
 
         TRACE(("StripSize: %d \n", state->bytes));
 
         /* realloc to fit whole strip */
+        /* malloc check above */
         new_data = realloc (state->buffer, state->bytes);
         if (!new_data) {
             state->errcode = IMAGING_CODEC_MEMORY;
```
