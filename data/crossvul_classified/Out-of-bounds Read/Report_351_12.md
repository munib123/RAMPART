# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_12
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_12`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 258-298 of the vulnerable file.

	assert(card && card->ctx && in_path);
	switch (in_path->type)
	{
	case SC_PATH_TYPE_DF_NAME:
	case SC_PATH_TYPE_FROM_CURRENT:
	case SC_PATH_TYPE_PARENT:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED);
	}
	assert(iso_ops && iso_ops->select_file);
	file_out_copy = file_out;
	r = iso_ops->select_file(card, in_path, file_out_copy);
	if (r || file_out_copy == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
	assert(file_out_copy);
	file = *file_out_copy;
	assert(file);
	if (file->sec_attr && file->sec_attr_len == SC_RTECP_SEC_ATTR_SIZE)
		set_acl_from_sec_attr(card, file);
	else
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (r)
		sc_file_free(file);
	else
	{
		assert(file_out);
		*file_out = file;
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_verify(sc_card_t *card, unsigned int type, int ref_qualifier,
		const u8 *data, size_t data_len, int *tries_left)
{
	sc_apdu_t apdu;
	int r, send_logout = 0;

	(void)type; /* no warning */
	assert(card && card->ctx && data);
	for (;;)
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -275,7 +275,7 @@
 		set_acl_from_sec_attr(card, file);
 	else
 		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
-	if (r)
+	if (r && !file_out)
 		sc_file_free(file);
 	else
 	{
```
