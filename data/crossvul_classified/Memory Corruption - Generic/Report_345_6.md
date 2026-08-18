# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 345_6
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `345_6`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 820-865 of the vulnerable file.

	LOG_TEST_RET(card->ctx, r, "Could not select SmartCard-HSM application");

	p15card->card->version.hw_major = 24;	/* JCOP 2.4.1r3 */
	p15card->card->version.hw_minor = 13;
	if (file && file->prop_attr && file->prop_attr_len >= 2) {
		p15card->card->version.fw_major = file->prop_attr[file->prop_attr_len - 2];
		p15card->card->version.fw_minor = file->prop_attr[file->prop_attr_len - 1];
	}

	sc_file_free(file);

	/* Read device certificate to determine serial number */
	if (priv->EF_C_DevAut && priv->EF_C_DevAut_len) {
		ptr = priv->EF_C_DevAut;
		len = priv->EF_C_DevAut_len;
	} else {
		len = sizeof efbin;
		r = read_file(p15card, (u8 *) "\x2F\x02", efbin, &len, 1);
		LOG_TEST_RET(card->ctx, r, "Skipping optional EF.C_DevAut");

		/* save EF_C_DevAut for further use */
		ptr = realloc(priv->EF_C_DevAut, len);
		if (ptr) {
			memcpy(ptr, efbin, len);
			priv->EF_C_DevAut = ptr;
			priv->EF_C_DevAut_len = len;
		}

		ptr = efbin;
	}

	memset(&devcert, 0 ,sizeof(devcert));
	r = sc_pkcs15emu_sc_hsm_decode_cvc(p15card, (const u8 **)&ptr, &len, &devcert);
	LOG_TEST_RET(card->ctx, r, "Could not decode EF.C_DevAut");

	sc_pkcs15emu_sc_hsm_read_tokeninfo(p15card);

	if (p15card->tokeninfo->label == NULL) {
		if (p15card->card->type == SC_CARD_TYPE_SC_HSM_GOID
				|| p15card->card->type == SC_CARD_TYPE_SC_HSM_SOC) {
			p15card->tokeninfo->label = strdup("GoID");
		} else {
			p15card->tokeninfo->label = strdup("SmartCard-HSM");
		}
		if (p15card->tokeninfo->label == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -837,12 +837,14 @@
 		r = read_file(p15card, (u8 *) "\x2F\x02", efbin, &len, 1);
 		LOG_TEST_RET(card->ctx, r, "Skipping optional EF.C_DevAut");
 
-		/* save EF_C_DevAut for further use */
-		ptr = realloc(priv->EF_C_DevAut, len);
-		if (ptr) {
-			memcpy(ptr, efbin, len);
-			priv->EF_C_DevAut = ptr;
-			priv->EF_C_DevAut_len = len;
+		if (len > 0) {
+			/* save EF_C_DevAut for further use */
+			ptr = realloc(priv->EF_C_DevAut, len);
+			if (ptr) {
+				memcpy(ptr, efbin, len);
+				priv->EF_C_DevAut = ptr;
+				priv->EF_C_DevAut_len = len;
+			}
 		}
 
 		ptr = efbin;
```
