# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3907_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3907_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 86-126 of the vulnerable file.

static BOOL update_read_bitmap_data(rdpUpdate* update, wStream* s, BITMAP_DATA* bitmapData)
{
	WINPR_UNUSED(update);
	if (Stream_GetRemainingLength(s) < 18)
		return FALSE;

	Stream_Read_UINT16(s, bitmapData->destLeft);
	Stream_Read_UINT16(s, bitmapData->destTop);
	Stream_Read_UINT16(s, bitmapData->destRight);
	Stream_Read_UINT16(s, bitmapData->destBottom);
	Stream_Read_UINT16(s, bitmapData->width);
	Stream_Read_UINT16(s, bitmapData->height);
	Stream_Read_UINT16(s, bitmapData->bitsPerPixel);
	Stream_Read_UINT16(s, bitmapData->flags);
	Stream_Read_UINT16(s, bitmapData->bitmapLength);

	if (bitmapData->flags & BITMAP_COMPRESSION)
	{
		if (!(bitmapData->flags & NO_BITMAP_COMPRESSION_HDR))
		{
			Stream_Read_UINT16(s,
			                   bitmapData->cbCompFirstRowSize); /* cbCompFirstRowSize (2 bytes) */
			Stream_Read_UINT16(s,
			                   bitmapData->cbCompMainBodySize); /* cbCompMainBodySize (2 bytes) */
			Stream_Read_UINT16(s, bitmapData->cbScanWidth);     /* cbScanWidth (2 bytes) */
			Stream_Read_UINT16(s,
			                   bitmapData->cbUncompressedSize); /* cbUncompressedSize (2 bytes) */
			bitmapData->bitmapLength = bitmapData->cbCompMainBodySize;
		}

		bitmapData->compressed = TRUE;
	}
	else
		bitmapData->compressed = FALSE;

	if (Stream_GetRemainingLength(s) < bitmapData->bitmapLength)
		return FALSE;

	if (bitmapData->bitmapLength > 0)
	{
		bitmapData->bitmapDataStream = malloc(bitmapData->bitmapLength);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,6 +103,9 @@
 	{
 		if (!(bitmapData->flags & NO_BITMAP_COMPRESSION_HDR))
 		{
+			if (Stream_GetRemainingLength(s) < 8)
+				return FALSE;
+
 			Stream_Read_UINT16(s,
 			                   bitmapData->cbCompFirstRowSize); /* cbCompFirstRowSize (2 bytes) */
 			Stream_Read_UINT16(s,
```
