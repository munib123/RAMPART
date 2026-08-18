# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 345_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `345_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 62-102 of the vulnerable file.

static int
sc_pkcs15emu_esteid_init (sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	unsigned char buff[128];
	int r, i;
	size_t field_length = 0, modulus_length = 0;
	sc_path_t tmppath;

	set_string (&p15card->tokeninfo->label, "ID-kaart");
	set_string (&p15card->tokeninfo->manufacturer_id, "AS Sertifitseerimiskeskus");

	/* Select application directory */
	sc_format_path ("3f00eeee5044", &tmppath);
	r = sc_select_file (card, &tmppath, NULL);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "select esteid PD failed");

	/* read the serial (document number) */
	r = sc_read_record (card, SC_ESTEID_PD_DOCUMENT_NR, buff, sizeof(buff), SC_RECORD_BY_REC_NR);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "read document number failed");
	buff[r] = '\0';
	set_string (&p15card->tokeninfo->serial_number, (const char *) buff);

	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION
				  | SC_PKCS15_TOKEN_EID_COMPLIANT
				  | SC_PKCS15_TOKEN_READONLY;

	/* add certificates */
	for (i = 0; i < 2; i++) {
		static const char *esteid_cert_names[2] = {
			"Isikutuvastus",
			"Allkirjastamine"};
		static char const *esteid_cert_paths[2] = {
			"3f00eeeeaace",
			"3f00eeeeddce"};
		static int esteid_cert_ids[2] = {1, 2};

		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;

		memset(&cert_info, 0, sizeof(cert_info));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,7 +79,7 @@
 	/* read the serial (document number) */
 	r = sc_read_record (card, SC_ESTEID_PD_DOCUMENT_NR, buff, sizeof(buff), SC_RECORD_BY_REC_NR);
 	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "read document number failed");
-	buff[r] = '\0';
+	buff[MIN((size_t) r, (sizeof buff)-1)] = '\0';
 	set_string (&p15card->tokeninfo->serial_number, (const char *) buff);
 
 	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION
```
