# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4402_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4402_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 606-646 of the vulnerable file.

	int tcos3, r;

	assert(card != NULL && crgram != NULL && out != NULL);
	ctx = card->ctx;
	tcos3=(card->type==SC_CARD_TYPE_TCOS_V3);
	data=(tcos_data *)card->drv_data;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
		"TCOS3:%d PKCS1:%d\n",tcos3,
		!!(data->pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1));

	sc_format_apdu(card, &apdu, crgram_len>255 ? SC_APDU_CASE_4_EXT : SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = crgram_len;

	apdu.data = sbuf;
	apdu.lc = apdu.datalen = crgram_len+1;
	sbuf[0] = tcos3 ? 0x00 : ((data->pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) ? 0x81 : 0x02);
	memcpy(sbuf+1, crgram, crgram_len);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1==0x90 && apdu.sw2==0x00) {
		size_t len= (apdu.resplen>outlen) ? outlen : apdu.resplen;
		unsigned int offset=0;
		if(tcos3 && (data->pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) && apdu.resp[0]==0 && apdu.resp[1]==2) {
			offset=2; while(offset<len && apdu.resp[offset]!=0) ++offset;
			offset=(offset<len-1) ? offset+1 : 0;
		}
		memcpy(out, apdu.resp+offset, len-offset);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len-offset);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}


/* Issue the SET PERMANENT command.  With ENABLE_NULLPIN set the
   NullPIN method will be activated, otherwise the permanent operation
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -623,6 +623,8 @@
 	apdu.data = sbuf;
 	apdu.lc = apdu.datalen = crgram_len+1;
 	sbuf[0] = tcos3 ? 0x00 : ((data->pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) ? 0x81 : 0x02);
+	if (sizeof sbuf - 1 < crgram_len)
+		return SC_ERROR_INVALID_ARGUMENTS;
 	memcpy(sbuf+1, crgram, crgram_len);
 
 	r = sc_transmit_apdu(card, &apdu);
```
