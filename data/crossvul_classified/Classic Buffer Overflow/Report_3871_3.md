# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 3871_3
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3871_3`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 154-194 of the vulnerable file.

    TRACE(("filepointer: %d \n",  fp));
    TRACE(("State: count %d, state %d, x %d, y %d, ystep %d\n", state->count, state->state,
           state->x, state->y, state->ystep));
    TRACE(("State: xsize %d, ysize %d, xoff %d, yoff %d \n", state->xsize, state->ysize,
           state->xoff, state->yoff));
    TRACE(("State: bits %d, bytes %d \n", state->bits, state->bytes));
    TRACE(("State: context %p \n", state->context));

    clientstate->loc = 0;
    clientstate->size = 0;
    clientstate->data = 0;
    clientstate->fp = fp;
    clientstate->ifd = offset;
    clientstate->eof = 0;

    return 1;
}


int ReadTile(TIFF* tiff, UINT32 col, UINT32 row, UINT32* buffer) {
    uint16 photometric;

    TIFFGetField(tiff, TIFFTAG_PHOTOMETRIC, &photometric);

    // To avoid dealing with YCbCr subsampling, let libtiff handle it
    if (photometric == PHOTOMETRIC_YCBCR) {
        UINT32 tile_width, tile_height, swap_line_size, i_row;
        UINT32* swap_line;

        TIFFGetField(tiff, TIFFTAG_TILEWIDTH, &tile_width);
        TIFFGetField(tiff, TIFFTAG_TILELENGTH, &tile_height);

        swap_line_size = tile_width * sizeof(UINT32);
        if (tile_width != swap_line_size / sizeof(UINT32)) {
            return -1;
        }

        /* Read the tile into an RGBA array */
        if (!TIFFReadRGBATile(tiff, col, row, buffer)) {
            return -1;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,7 +171,7 @@
 
 
 int ReadTile(TIFF* tiff, UINT32 col, UINT32 row, UINT32* buffer) {
-    uint16 photometric;
+    uint16 photometric = 0;
 
     TIFFGetField(tiff, TIFFTAG_PHOTOMETRIC, &photometric);
 
@@ -228,7 +228,7 @@
 }
 
 int ReadStrip(TIFF* tiff, UINT32 row, UINT32* buffer) {
-    uint16 photometric;
+    uint16 photometric = 0; // init to not PHOTOMETRIC_YCBCR
     TIFFGetField(tiff, TIFFTAG_PHOTOMETRIC, &photometric);
 
     // To avoid dealing with YCbCr subsampling, let libtiff handle it
@@ -363,6 +363,13 @@
         
         state->bytes = row_byte_size * tile_length;
 
+        if (TIFFTileSize(tiff) > state->bytes) {
+            // If the strip size as expected by LibTiff isn't what we're expecting, abort.
+            state->errcode = IMAGING_CODEC_MEMORY;
+            TIFFClose(tiff);
+            return -1;
+        }
+
         /* realloc to fit whole tile */
         /* malloc check above */
         new_data = realloc (state->buffer, state->bytes);
@@ -424,10 +431,20 @@
             TIFFClose(tiff);
             return -1;
         }
-        
+
         state->bytes = rows_per_strip * row_byte_size;
 
         TRACE(("StripSize: %d \n", state->bytes));
+
+        if (TIFFStripSize(tiff) > state->bytes) {
+            // If the strip size as expected by LibTiff isn't what we're expecting, abort.
+            // man:   TIFFStripSize returns the equivalent size for a strip of data as it would be returned in a
+            //        call to TIFFReadEncodedStrip ...
+
+            state->errcode = IMAGING_CODEC_MEMORY;
+            TIFFClose(tiff);
+            return -1;
+        }
 
         /* realloc to fit whole strip */
         /* malloc check above */
```
