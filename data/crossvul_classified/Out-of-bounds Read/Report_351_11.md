# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_11
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_11`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 556-596 of the vulnerable file.

/* TODO: - DEE look later at tag vs size read too */
	if (r < 0) {
		sc_log(card->ctx, "Card returned error ");
		goto err;
	}

	/*
	 * See how much we read and make sure it is asn1
	 * if not, return 0 indicating no data found
	 */


	rbuflen = 0;  /* in case rseplen < 3  i.e. not parseable */
	/* we may only be using get data to test the security status of the card, so zero length is OK */
	if ( recvbuflen && recvbuf && apdu.resplen > 3 && priv->pin_cmd_noparse != 1) {
		*recvbuflen = 0;
		/* we should have all the tag data, so we have to tell sc_asn1_find_tag
		 * the buffer is bigger, so it will not produce "ASN1.tag too long!" */

		body = rbuf;
		if (sc_asn1_read_tag(&body, 0xffff, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS
				|| body == NULL)  {
			/* only early beta cards had this problem */
			sc_log(card->ctx, "***** received buffer tag MISSING ");
			body = rbuf;
			/* some readers/cards might return 6c 00 */
			if (apdu.sw1 == 0x61  || apdu.sw2 == 0x6c )
				bodylen = 12000;
			else
				bodylen = apdu.resplen;
		}

		rbuflen = body - rbuf + bodylen;

		/* if using internal buffer, alloc new one */
		if (rbuf == rbufinitbuf) {
			*recvbuf = malloc(rbuflen);
			if (*recvbuf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -573,7 +573,7 @@
 		 * the buffer is bigger, so it will not produce "ASN1.tag too long!" */
 
 		body = rbuf;
-		if (sc_asn1_read_tag(&body, 0xffff, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS
+		if (sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS
 				|| body == NULL)  {
 			/* only early beta cards had this problem */
 			sc_log(card->ctx, "***** received buffer tag MISSING ");
@@ -3033,12 +3033,13 @@
 			 *   73 66 74 65 20 63 64 31 34 34
 			 * will check for 73 66 74 65
 			 */
-			else if (card->reader->atr_info.hist_bytes_len >= 4 &&
-					!(memcmp(card->reader->atr_info.hist_bytes, "sfte", 4))) {
+			else if (card->reader->atr_info.hist_bytes_len >= 4
+					&& !(memcmp(card->reader->atr_info.hist_bytes, "sfte", 4))) {
 				type = SC_CARD_TYPE_PIV_II_GI_DE;
 			}
 
-			else if (card->reader->atr_info.hist_bytes[0] == 0x80u) { /* compact TLV */
+			else if (card->reader->atr_info.hist_bytes_len > 0
+					&& card->reader->atr_info.hist_bytes[0] == 0x80u) { /* compact TLV */
 				size_t datalen;
 				const u8 *data = sc_compacttlv_find_tag(card->reader->atr_info.hist_bytes + 1,
 									card->reader->atr_info.hist_bytes_len - 1,
```
