# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3954_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3954_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 562-602 of the vulnerable file.


	glyph = glyphCache->glyphCache[id].entries[index];

	if (!glyph)
		WLog_ERR(TAG, "no glyph found at cache index: %" PRIu32 " in cache id: %" PRIu32 "", index,
		         id);

	return glyph;
}

BOOL glyph_cache_put(rdpGlyphCache* glyphCache, UINT32 id, UINT32 index, rdpGlyph* glyph)
{
	rdpGlyph* prevGlyph;

	if (id > 9)
	{
		WLog_ERR(TAG, "invalid glyph cache id: %" PRIu32 "", id);
		return FALSE;
	}

	if (index > glyphCache->glyphCache[id].number)
	{
		WLog_ERR(TAG, "invalid glyph cache index: %" PRIu32 " in cache id: %" PRIu32 "", index, id);
		return FALSE;
	}

	WLog_Print(glyphCache->log, WLOG_DEBUG, "GlyphCachePut: id: %" PRIu32 " index: %" PRIu32 "", id,
	           index);
	prevGlyph = glyphCache->glyphCache[id].entries[index];

	if (prevGlyph)
		prevGlyph->Free(glyphCache->context, prevGlyph);

	glyphCache->glyphCache[id].entries[index] = glyph;
	return TRUE;
}

const void* glyph_cache_fragment_get(rdpGlyphCache* glyphCache, UINT32 index, UINT32* size)
{
	void* fragment;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -579,7 +579,7 @@
 		return FALSE;
 	}
 
-	if (index > glyphCache->glyphCache[id].number)
+	if (index >= glyphCache->glyphCache[id].number)
 	{
 		WLog_ERR(TAG, "invalid glyph cache index: %" PRIu32 " in cache id: %" PRIu32 "", index, id);
 		return FALSE;
```
