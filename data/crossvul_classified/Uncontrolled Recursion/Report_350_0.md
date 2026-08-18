# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 350_0
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `350_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 810-850 of the vulnerable file.

static int
iasecc_select_file(struct sc_card *card, const struct sc_path *path,
		 struct sc_file **file_out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path lpath;
	int cache_valid = card->cache.valid, df_from_cache = 0;
	int rv, ii;

	LOG_FUNC_CALLED(ctx);
	memcpy(&lpath, path, sizeof(struct sc_path));
	if (file_out)
		*file_out = NULL;

	sc_log(ctx,
	       "iasecc_select_file(card:%p) path.len %"SC_FORMAT_LEN_SIZE_T"u; path.type %i; aid_len %"SC_FORMAT_LEN_SIZE_T"u",
	       card, path->len, path->type, path->aid.len);
	sc_log(ctx, "iasecc_select_file() path:%s", sc_print_path(path));

	sc_print_cache(card);
	if (lpath.len >= 2 && lpath.value[0] == 0x3F && lpath.value[1] == 0x00)   {
		sc_log(ctx, "EF.ATR(aid:'%s')", card->ef_atr ? sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len) : "");

		rv = iasecc_select_mf(card, file_out);
		LOG_TEST_RET(ctx, rv, "MF selection error");

		if (lpath.len >= 2 && lpath.value[0] == 0x3F && lpath.value[1] == 0x00)	   {
			memmove(&lpath.value[0], &lpath.value[2], lpath.len - 2);
			lpath.len -=  2;
		}
	}

	if (lpath.aid.len)	{
		struct sc_file *file = NULL;
		struct sc_path ppath;

		sc_log(ctx,
		       "iasecc_select_file() select parent AID:%p/%"SC_FORMAT_LEN_SIZE_T"u",
		       lpath.aid.value, lpath.aid.len);
		sc_log(ctx, "iasecc_select_file() select parent AID:%s", sc_dump_hex(lpath.aid.value, lpath.aid.len));
		memset(&ppath, 0, sizeof(ppath));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -827,16 +827,16 @@
 	sc_log(ctx, "iasecc_select_file() path:%s", sc_print_path(path));
 
 	sc_print_cache(card);
-	if (lpath.len >= 2 && lpath.value[0] == 0x3F && lpath.value[1] == 0x00)   {
+	if (path->type != SC_PATH_TYPE_DF_NAME
+			&& lpath.len >= 2
+			&& lpath.value[0] == 0x3F && lpath.value[1] == 0x00)   {
 		sc_log(ctx, "EF.ATR(aid:'%s')", card->ef_atr ? sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len) : "");
 
 		rv = iasecc_select_mf(card, file_out);
 		LOG_TEST_RET(ctx, rv, "MF selection error");
 
-		if (lpath.len >= 2 && lpath.value[0] == 0x3F && lpath.value[1] == 0x00)	   {
-			memmove(&lpath.value[0], &lpath.value[2], lpath.len - 2);
-			lpath.len -=  2;
-		}
+		memmove(&lpath.value[0], &lpath.value[2], lpath.len - 2);
+		lpath.len -=  2;
 	}
 
 	if (lpath.aid.len)	{
```
