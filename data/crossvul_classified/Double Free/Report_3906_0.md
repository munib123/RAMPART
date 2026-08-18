# CrossVul Fix Pair: Double Free in c
**Pair ID:** 3906_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3906_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 2144-2184 of the vulnerable file.


	Stream_Read_UINT16(s, cache_bitmap_v3->cacheIndex); /* cacheIndex (2 bytes) */
	Stream_Read_UINT32(s, cache_bitmap_v3->key1);       /* key1 (4 bytes) */
	Stream_Read_UINT32(s, cache_bitmap_v3->key2);       /* key2 (4 bytes) */
	bitmapData = &cache_bitmap_v3->bitmapData;
	Stream_Read_UINT8(s, bitmapData->bpp);

	if ((bitmapData->bpp < 1) || (bitmapData->bpp > 32))
	{
		WLog_Print(update->log, WLOG_ERROR, "invalid bpp value %" PRIu32 "", bitmapData->bpp);
		goto fail;
	}

	Stream_Seek_UINT8(s);                      /* reserved1 (1 byte) */
	Stream_Seek_UINT8(s);                      /* reserved2 (1 byte) */
	Stream_Read_UINT8(s, bitmapData->codecID); /* codecID (1 byte) */
	Stream_Read_UINT16(s, bitmapData->width);  /* width (2 bytes) */
	Stream_Read_UINT16(s, bitmapData->height); /* height (2 bytes) */
	Stream_Read_UINT32(s, new_len);            /* length (4 bytes) */

	if (Stream_GetRemainingLength(s) < new_len)
		goto fail;

	new_data = (BYTE*)realloc(bitmapData->data, new_len);

	if (!new_data)
		goto fail;

	bitmapData->data = new_data;
	bitmapData->length = new_len;
	Stream_Read(s, bitmapData->data, bitmapData->length);
	return cache_bitmap_v3;
fail:
	free_cache_bitmap_v3_order(update->context, cache_bitmap_v3);
	return NULL;
}
int update_approximate_cache_bitmap_v3_order(CACHE_BITMAP_V3_ORDER* cache_bitmap_v3, UINT16* flags)
{
	BITMAP_DATA_EX* bitmapData = &cache_bitmap_v3->bitmapData;
	return 64 + bitmapData->length;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2161,7 +2161,7 @@
 	Stream_Read_UINT16(s, bitmapData->height); /* height (2 bytes) */
 	Stream_Read_UINT32(s, new_len);            /* length (4 bytes) */
 
-	if (Stream_GetRemainingLength(s) < new_len)
+	if ((new_len == 0) || (Stream_GetRemainingLength(s) < new_len))
 		goto fail;
 
 	new_data = (BYTE*)realloc(bitmapData->data, new_len);
```
