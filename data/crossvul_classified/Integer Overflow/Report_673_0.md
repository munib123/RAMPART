# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 673_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `673_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 124-164 of the vulnerable file.

}

static BOOL gdi_Bitmap_Paint(rdpContext* context, rdpBitmap* bitmap)
{
	gdiBitmap* gdi_bitmap = (gdiBitmap*) bitmap;
	UINT32 width = bitmap->right - bitmap->left + 1;
	UINT32 height = bitmap->bottom - bitmap->top + 1;
	return gdi_BitBlt(context->gdi->primary->hdc,
	                  bitmap->left, bitmap->top,
	                  width, height, gdi_bitmap->hdc,
	                  0, 0, GDI_SRCCOPY, &context->gdi->palette);
}

static BOOL gdi_Bitmap_Decompress(rdpContext* context, rdpBitmap* bitmap,
                                  const BYTE* pSrcData, UINT32 DstWidth, UINT32 DstHeight,
                                  UINT32 bpp, UINT32 length, BOOL compressed,
                                  UINT32 codecId)
{
	UINT32 SrcSize = length;
	rdpGdi* gdi = context->gdi;
	bitmap->compressed = FALSE;
	bitmap->format = gdi->dstFormat;
	bitmap->length = DstWidth * DstHeight * GetBytesPerPixel(bitmap->format);
	bitmap->data = (BYTE*) _aligned_malloc(bitmap->length, 16);

	if (!bitmap->data)
		return FALSE;

	if (compressed)
	{
		if (bpp < 32)
		{
			if (!interleaved_decompress(context->codecs->interleaved,
			                            pSrcData, SrcSize,
			                            DstWidth, DstHeight,
			                            bpp,
			                            bitmap->data, bitmap->format,
			                            0, 0, 0, DstWidth, DstHeight,
			                            &gdi->palette))
				return FALSE;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,9 +141,17 @@
 {
 	UINT32 SrcSize = length;
 	rdpGdi* gdi = context->gdi;
+	UINT32 size = DstWidth * DstHeight;
 	bitmap->compressed = FALSE;
 	bitmap->format = gdi->dstFormat;
-	bitmap->length = DstWidth * DstHeight * GetBytesPerPixel(bitmap->format);
+
+	if ((GetBytesPerPixel(bitmap->format) == 0) ||
+	    (DstWidth == 0) || (DstHeight == 0) || (DstWidth > UINT32_MAX / DstHeight) ||
+	    (size > (UINT32_MAX / GetBytesPerPixel(bitmap->format))))
+		return FALSE;
+
+	size *= GetBytesPerPixel(bitmap->format);
+	bitmap->length = size;
 	bitmap->data = (BYTE*) _aligned_malloc(bitmap->length, 16);
 
 	if (!bitmap->data)
```
