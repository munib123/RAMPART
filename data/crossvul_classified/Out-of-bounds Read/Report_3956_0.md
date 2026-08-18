# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3956_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3956_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 264-305 of the vulnerable file.

	update->primary->MemBlt = update_gdi_memblt;
	update->primary->Mem3Blt = update_gdi_mem3blt;
	update->secondary->CacheBitmap = update_gdi_cache_bitmap;
	update->secondary->CacheBitmapV2 = update_gdi_cache_bitmap_v2;
	update->secondary->CacheBitmapV3 = update_gdi_cache_bitmap_v3;
	update->BitmapUpdate = gdi_bitmap_update;
}

rdpBitmapCache* bitmap_cache_new(rdpSettings* settings)
{
	int i;
	rdpBitmapCache* bitmapCache;
	bitmapCache = (rdpBitmapCache*)calloc(1, sizeof(rdpBitmapCache));

	if (!bitmapCache)
		return NULL;

	bitmapCache->settings = settings;
	bitmapCache->update = ((freerdp*)settings->instance)->update;
	bitmapCache->context = bitmapCache->update->context;
	bitmapCache->maxCells = settings->BitmapCacheV2NumCells;
	bitmapCache->cells = (BITMAP_V2_CELL*)calloc(bitmapCache->maxCells, sizeof(BITMAP_V2_CELL));

	if (!bitmapCache->cells)
		goto fail;

	for (i = 0; i < (int)bitmapCache->maxCells; i++)
	{
		bitmapCache->cells[i].number = settings->BitmapCacheV2CellInfo[i].numEntries;
		/* allocate an extra entry for BITMAP_CACHE_WAITING_LIST_INDEX */
		bitmapCache->cells[i].entries =
		    (rdpBitmap**)calloc((bitmapCache->cells[i].number + 1), sizeof(rdpBitmap*));

		if (!bitmapCache->cells[i].entries)
			goto fail;
	}

	return bitmapCache;
fail:

	if (bitmapCache->cells)
	{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -281,11 +281,12 @@
 	bitmapCache->settings = settings;
 	bitmapCache->update = ((freerdp*)settings->instance)->update;
 	bitmapCache->context = bitmapCache->update->context;
+	bitmapCache->cells =
+	    (BITMAP_V2_CELL*)calloc(settings->BitmapCacheV2NumCells, sizeof(BITMAP_V2_CELL));
+
+	if (!bitmapCache->cells)
+		goto fail;
 	bitmapCache->maxCells = settings->BitmapCacheV2NumCells;
-	bitmapCache->cells = (BITMAP_V2_CELL*)calloc(bitmapCache->maxCells, sizeof(BITMAP_V2_CELL));
-
-	if (!bitmapCache->cells)
-		goto fail;
 
 	for (i = 0; i < (int)bitmapCache->maxCells; i++)
 	{
```
