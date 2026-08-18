# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1179_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1179_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 391-432 of the vulnerable file.

	GifByteType **extension )
{
	if( DGifGetCodeNext( gif->file, extension ) == GIF_ERROR ) {
		vips_foreign_load_gif_error( gif ); 
		return( -1 ); 
	}

	if( *extension ) 
		VIPS_DEBUG_MSG( "gifload: CODE_NEXT\n" ); 

	return( 0 );
}

/* Quickly scan an image record.
 */
static int
vips_foreign_load_gif_scan_image( VipsForeignLoadGif *gif ) 
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );
	GifFileType *file = gif->file;
	ColorMapObject *map = file->Image.ColorMap ?
		file->Image.ColorMap : file->SColorMap;

	GifByteType *extension;

	if( DGifGetImageDesc( gif->file ) == GIF_ERROR ) {
		vips_foreign_load_gif_error( gif ); 
		return( -1 );
	}

	/* Check that the frame looks sane. Perhaps giflib checks
	 * this for us.
	 */
	if( file->Image.Left < 0 ||
		file->Image.Width < 1 ||
		file->Image.Width > 10000 ||
		file->Image.Left + file->Image.Width > file->SWidth ||
		file->Image.Top < 0 ||
		file->Image.Height < 1 ||
		file->Image.Height > 10000 ||
		file->Image.Top + file->Image.Height > file->SHeight ) {
		vips_error( class->nickname, "%s", _( "bad frame size" ) ); 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -408,9 +408,8 @@
 {
 	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );
 	GifFileType *file = gif->file;
-	ColorMapObject *map = file->Image.ColorMap ?
-		file->Image.ColorMap : file->SColorMap;
-
+
+	ColorMapObject *map;
 	GifByteType *extension;
 
 	if( DGifGetImageDesc( gif->file ) == GIF_ERROR ) {
@@ -435,6 +434,7 @@
 
 	/* Test for a non-greyscale colourmap for this frame.
 	 */
+	map = file->Image.ColorMap ? file->Image.ColorMap : file->SColorMap;
 	if( !gif->has_colour &&
 		map ) {
 		int i;
```
