# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_5
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_5`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1391-1431 of the vulnerable file.

	apdu.data    = sbuf;
	apdu.lc      = 2;
	apdu.datalen = 2;

	r = entersafe_transmit_apdu(card, &apdu,0,0,0,0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, sc_check_sw(card,apdu.sw1,apdu.sw2),"EnterSafe generate keypair failed");

	/* read public key via READ PUBLIC KEY */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xE6,  0x2A, data->key_id);
	apdu.cla     = 0x80;
	apdu.resp    = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le      = 256;
	r = entersafe_transmit_apdu(card, &apdu,0,0,0,0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, sc_check_sw(card,apdu.sw1,apdu.sw2),"EnterSafe get pukey failed");

	data->modulus = malloc(len);
	if (!data->modulus)
		 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_OUT_OF_MEMORY);

	p=rbuf;
	assert(*p=='E');
	p+=2+p[1];
	/* N */
	assert(*p=='N');
	++p;
	if(*p++>0x80)
	{
		 u8 len_bytes=(*(p-1))&0x0f;
		 size_t module_len=0;
		 while(len_bytes!=0)
		 {
			  module_len=module_len<<8;
			  module_len+=*p++;
			  --len_bytes;
		 }
	}

	entersafe_reverse_buffer(p,len);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1408,13 +1408,15 @@
 
 	data->modulus = malloc(len);
 	if (!data->modulus)
-		 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_OUT_OF_MEMORY);
+		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_OUT_OF_MEMORY);
 
 	p=rbuf;
-	assert(*p=='E');
+	if (*p!='E')
+		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);
 	p+=2+p[1];
 	/* N */
-	assert(*p=='N');
+	if (*p!='N')
+		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);
 	++p;
 	if(*p++>0x80)
 	{
```
