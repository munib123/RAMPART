# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 152-192 of the vulnerable file.

	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)
		table = ief_amode_table;
	else
		return SC_ERROR_INVALID_ARGUMENTS;
	for (; table->am != 0; table++) {
		if (table->am & am)
			sc_file_add_acl_entry(file, table->sc, meth, ac);
	}
	return SC_SUCCESS;
}

/* Convert asepcos security attributes to opensc access conditions.
 */
static int asepcos_parse_sec_attr(sc_card_t *card, sc_file_t *file, const u8 *buf,
	size_t len)
{
	const u8 *p = buf;

	while (len != 0) {
		unsigned int amode, tlen = 3;
		if (len < 5 && p[0] != 0x80 && p[1] != 0x01) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "invalid access mode encoding");
			return SC_ERROR_INTERNAL;
		}
		amode = p[2];
		if (p[3] == 0x90 && p[4] == 0x00) {
			int r = set_sec_attr(file, amode, 0, SC_AC_NONE);
			if (r != SC_SUCCESS) 
				return r;
			tlen += 2;
		} else if (p[3] == 0x97 && p[4] == 0x00) {
			int r = set_sec_attr(file, amode, 0, SC_AC_NEVER);
			if (r != SC_SUCCESS) 
				return r;
			tlen += 2;
		} else if (p[3] == 0xA0 && len >= 4U + p[4]) {
			/* TODO: support OR expressions */
			int r = set_sec_attr(file, amode, p[5], SC_AC_CHV);
			if (r != SC_SUCCESS)
				return r;
			tlen += 2 + p[4]; /* FIXME */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -169,7 +169,7 @@
 
 	while (len != 0) {
 		unsigned int amode, tlen = 3;
-		if (len < 5 && p[0] != 0x80 && p[1] != 0x01) {
+		if (len < 5 || p[0] != 0x80 || p[1] != 0x01) {
 			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "invalid access mode encoding");
 			return SC_ERROR_INTERNAL;
 		}
```
