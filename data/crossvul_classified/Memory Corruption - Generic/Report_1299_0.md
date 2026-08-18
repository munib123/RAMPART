# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1299_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1299_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 52-92 of the vulnerable file.

#ifdef ENABLE_ZLIB
#include "compression.h"
#endif
#include "iso7816.h"
#include "card-cac-common.h"

/*
 *  CAC hardware and APDU constants
 */
#define CAC_INS_GET_CERTIFICATE       0x36  /* CAC1 command to read a certificate */

/*
 * OLD cac read certificate, only use with CAC-1 card.
 */
static int cac_cac1_get_certificate(sc_card_t *card, u8 **out_buf, size_t *out_len)
{
	u8 buf[CAC_MAX_SIZE];
	u8 *out_ptr;
	size_t size = 0;
	size_t left = 0;
	size_t len, next_len;
	sc_apdu_t apdu;
	int r = SC_SUCCESS;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* get the size */
	size = left = *out_buf ? *out_len : sizeof(buf);
	out_ptr = *out_buf ? *out_buf : buf;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, CAC_INS_GET_CERTIFICATE, 0, 0 );
	next_len = MIN(left, 100);
	for (; left > 0; left -= len, out_ptr += len) {
		len = next_len;
		apdu.resp = out_ptr;
		apdu.le = len;
		apdu.resplen = left;
		r = sc_transmit_apdu(card, &apdu);
		if (r < 0) {
			break;
		}
		if (apdu.resplen == 0) {
			r = SC_ERROR_INTERNAL;
			break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,7 +69,7 @@
 	u8 *out_ptr;
 	size_t size = 0;
 	size_t left = 0;
-	size_t len, next_len;
+	size_t len;
 	sc_apdu_t apdu;
 	int r = SC_SUCCESS;
 	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
@@ -77,9 +77,8 @@
 	size = left = *out_buf ? *out_len : sizeof(buf);
 	out_ptr = *out_buf ? *out_buf : buf;
 	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, CAC_INS_GET_CERTIFICATE, 0, 0 );
-	next_len = MIN(left, 100);
-	for (; left > 0; left -= len, out_ptr += len) {
-		len = next_len;
+	len = MIN(left, 100);
+	for (; left > 0;) { /* Increments for readability in the end of the function */
 		apdu.resp = out_ptr;
 		apdu.le = len;
 		apdu.resplen = left;
@@ -98,7 +97,10 @@
 			left -= len;
 			break;
 		}
-		next_len = MIN(left, apdu.sw2);
+		/* Adjust the lengths */
+		left -= len;
+		out_ptr += len;
+		len = MIN(left, apdu.sw2);
 	}
 	if (r < 0) {
 		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
@@ -128,7 +130,7 @@
 	int r = 0;
 	u8 *val = NULL;
 	u8 *cert_ptr;
-	size_t val_len;
+	size_t val_len = 0;
 	size_t len, cert_len;
 	u8 cert_type;
 
```
