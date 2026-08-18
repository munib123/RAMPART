# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_8
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_8`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2531-2571 of the vulnerable file.

		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "serial number parse error");

	iin->mii = (rbuf[2] >> 4) & 0x0F;

	iin->country = 0;
	for (ii=5; ii<8; ii++)   {
		iin->country *= 10;
		iin->country += (rbuf[ii/2] >> ((ii & 0x01) ? 0 : 4)) & 0x0F;
	}

	iin->issuer_id = 0;
	for (ii=8; ii<10; ii++)   {
		iin->issuer_id *= 10;
		iin->issuer_id += (rbuf[ii/2] >> (ii & 0x01 ? 0 : 4)) & 0x0F;
	}

	offs = rbuf[1] > 8 ? rbuf[1] - 8 : 0;
	if (card->type == SC_CARD_TYPE_IASECC_SAGEM)   {
		/* 5A 0A 92 50 00 20 10 10 25 00 01 3F */
		/*            00 02 01 01 02 50 00 13  */
		for (ii=0; ii < rbuf[1] - offs; ii++)
			*(card->serialnr.value + ii) = ((rbuf[ii + offs + 1] & 0x0F) << 4)
				+ ((rbuf[ii + offs + 2] & 0xF0) >> 4) ;
		card->serialnr.len = ii;
	}
	else   {
		for (ii=0; ii < rbuf[1] - offs; ii++)
			*(card->serialnr.value + ii) = rbuf[ii + offs + 2];
		card->serialnr.len = ii;
	}

	do  {
		char txt[0x200];

		for (ii=0;ii<card->serialnr.len;ii++)
			sprintf(txt + ii*2, "%02X", *(card->serialnr.value + ii));

		sc_log(ctx, "serial number '%s'; mii %i; country %i; issuer_id %li", txt, iin->mii, iin->country, iin->issuer_id);
	} while(0);

end:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2548,7 +2548,7 @@
 	if (card->type == SC_CARD_TYPE_IASECC_SAGEM)   {
 		/* 5A 0A 92 50 00 20 10 10 25 00 01 3F */
 		/*            00 02 01 01 02 50 00 13  */
-		for (ii=0; ii < rbuf[1] - offs; ii++)
+		for (ii=0; (ii < rbuf[1] - offs) && (ii + offs + 2 < sizeof(rbuf)); ii++)
 			*(card->serialnr.value + ii) = ((rbuf[ii + offs + 1] & 0x0F) << 4)
 				+ ((rbuf[ii + offs + 2] & 0xF0) >> 4) ;
 		card->serialnr.len = ii;
```
