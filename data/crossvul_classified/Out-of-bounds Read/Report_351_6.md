# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_6
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_6`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 723-763 of the vulnerable file.


	/* increase icv */
	for (; i >= 0; i--) {
		if (exdata->icv_mac[i] == 0xff) {
			exdata->icv_mac[i] = 0;
		}
		else {
			exdata->icv_mac[i]++;
			break;
		}
	}

	/* calculate MAC */
	memset(icv, 0, sizeof(icv));
	memcpy(icv, exdata->icv_mac, 16);
	if (KEY_TYPE_AES == key_type) {
		aes128_encrypt_cbc(exdata->sk_mac, 16, icv, apdu_buf, mac_len, mac);
		memcpy(mac_tlv + 2, &mac[mac_len - 16], 8);
	}
	else {
		unsigned char iv[8] = { 0 };
		unsigned char tmp[8] = { 0 };
		des_encrypt_cbc(exdata->sk_mac, 8, icv, apdu_buf, mac_len, mac);
		des_decrypt_cbc(&exdata->sk_mac[8], 8, iv, &mac[mac_len - 8], 8, tmp);
		memset(iv, 0x00, 8);
		des_encrypt_cbc(exdata->sk_mac, 8, iv, tmp, 8, mac_tlv + 2);
	}

	*mac_tlv_len = 2 + 8;
	return 0;
}


/* According to GlobalPlatform Card Specification's SCP01
 * encode APDU from
 * CLA INS P1 P2 [Lc] Data [Le]
 * to
 * CLA INS P1 P2 Lc' Data' [Le]
 * where
 * Data'=Data(TLV)+Le(TLV)+MAC(TLV) */
static int
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -740,11 +740,11 @@
 		memcpy(mac_tlv + 2, &mac[mac_len - 16], 8);
 	}
 	else {
-		unsigned char iv[8] = { 0 };
+		unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
 		unsigned char tmp[8] = { 0 };
 		des_encrypt_cbc(exdata->sk_mac, 8, icv, apdu_buf, mac_len, mac);
 		des_decrypt_cbc(&exdata->sk_mac[8], 8, iv, &mac[mac_len - 8], 8, tmp);
-		memset(iv, 0x00, 8);
+		memset(iv, 0x00, sizeof iv);
 		des_encrypt_cbc(exdata->sk_mac, 8, iv, tmp, 8, mac_tlv + 2);
 	}
 
@@ -903,9 +903,9 @@
  * SW12(TLV)=0x99|0x02|SW1+SW2
  * MAC(TLV)=0x8e|0x08|MAC */
 static int
-decrypt_response(struct sc_card *card, unsigned char *in, unsigned char *out, size_t * out_len)
-{
-	size_t in_len;
+decrypt_response(struct sc_card *card, unsigned char *in, size_t inlen, unsigned char *out, size_t * out_len)
+{
+	size_t cipher_len;
 	size_t i;
 	unsigned char iv[16] = { 0 };
 	unsigned char plaintext[4096] = { 0 };
@@ -922,37 +922,40 @@
 
 	/* parse cipher length */
 	if (0x01 == in[2] && 0x82 != in[1]) {
-		in_len = in[1];
+		cipher_len = in[1];
 		i = 3;
 	}
 	else if (0x01 == in[3] && 0x81 == in[1]) {
-		in_len = in[2];
+		cipher_len = in[2];
 		i = 4;
 	}
 	else if (0x01 == in[4] && 0x82 == in[1]) {
-		in_len = in[2] * 0x100;
-		in_len += in[3];
+		cipher_len = in[2] * 0x100;
+		cipher_len += in[3];
 		i = 5;
 	}
 	else {
 		return -1;
 	}
 
+	if (cipher_len < 2 || i+cipher_len > inlen || cipher_len > sizeof plaintext)
+		return -1;
+
 	/* decrypt */
 	if (KEY_TYPE_AES == exdata->smtype)
-		aes128_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], in_len - 1, plaintext);
+		aes128_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], cipher_len - 1, plaintext);
 	else
-		des3_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], in_len - 1, plaintext);
+		des3_decrypt_cbc(exdata->sk_enc, 16, iv, &in[i], cipher_len - 1, plaintext);
 
 	/* unpadding */
-	while (0x80 != plaintext[in_len - 2] && (in_len - 2 > 0))
-		in_len--;
-
-	if (2 == in_len)
+	while (0x80 != plaintext[cipher_len - 2] && (cipher_len - 2 > 0))
+		cipher_len--;
+
+	if (2 == cipher_len)
 		return -1;
 
-	memcpy(out, plaintext, in_len - 2);
-	*out_len = in_len - 2;
+	memcpy(out, plaintext, cipher_len - 2);
+	*out_len = cipher_len - 2;
 	return 0;
 }
 
@@ -974,7 +977,7 @@
 	r = sc_check_sw(card, sm->sw1, sm->sw2);
 	if (r == SC_SUCCESS) {
 		if (exdata->sm) {
-			if (0 != decrypt_response(card, sm->resp, plain->resp, &len))
+			if (0 != decrypt_response(card, sm->resp, sm->resplen, plain->resp, &len))
 				return SC_ERROR_CARD_CMD_FAILED;
 		}
 		else {
```
