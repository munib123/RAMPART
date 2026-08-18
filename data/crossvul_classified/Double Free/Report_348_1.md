# CrossVul Fix Pair: Double Free in c
**Pair ID:** 348_1
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `348_1`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 934-974 of the vulnerable file.

		cipher_len += in[3];
		i = 5;
	}
	else {
		return -1;
	}

	if (cipher_len < 2 || i+cipher_len > inlen || cipher_len > sizeof plaintext)
		return -1;

	/* decrypt */
	if (KEY_TYPE_AES == exdata->smtype)
		aes128_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], cipher_len - 1, plaintext);
	else
		des3_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], cipher_len - 1, plaintext);

	/* unpadding */
	while (0x80 != plaintext[cipher_len - 2] && (cipher_len - 2 > 0))
		cipher_len--;

	if (2 == cipher_len)
		return -1;

	memcpy(out, plaintext, cipher_len - 2);
	*out_len = cipher_len - 2;
	return 0;
}


static int
epass2003_sm_unwrap_apdu(struct sc_card *card, struct sc_apdu *sm, struct sc_apdu *plain)
{
	int r;
	size_t len = 0;
	epass2003_exdata *exdata = NULL;

	if (!card->drv_data) 
		return SC_ERROR_INVALID_ARGUMENTS;

	exdata = (epass2003_exdata *)card->drv_data;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -951,7 +951,7 @@
 	while (0x80 != plaintext[cipher_len - 2] && (cipher_len - 2 > 0))
 		cipher_len--;
 
-	if (2 == cipher_len)
+	if (2 == cipher_len || *out_len < cipher_len - 2)
 		return -1;
 
 	memcpy(out, plaintext, cipher_len - 2);
@@ -977,6 +977,7 @@
 	r = sc_check_sw(card, sm->sw1, sm->sw2);
 	if (r == SC_SUCCESS) {
 		if (exdata->sm) {
+			len = plain->resplen;
 			if (0 != decrypt_response(card, sm->resp, sm->resplen, plain->resp, &len))
 				return SC_ERROR_CARD_CMD_FAILED;
 		}
```
