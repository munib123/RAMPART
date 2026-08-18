# CrossVul Fix Pair: Double Free in c
**Pair ID:** 348_5
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `348_5`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 191-231 of the vulnerable file.

	    sc_log(card->ctx, "Invalid object size: %"SC_FORMAT_LEN_SIZE_T"u",
		   objlen);
	    return SC_ERROR_INTERNAL;
	}

	/* It looks like the first thing in the block is a table of
	 * which keys are allocated. The table is small and is in the
	 * first 248 bytes. Example for a card with 10 key containers:
	 * 01 f0 00 03 03 b0 00 03     <=  1st key unallocated
	 * 01 f0 00 04 03 b0 00 04     <=  2nd key unallocated
	 * 01 fe 14 00 05 03 b0 00 05  <=  3rd key allocated
	 * 01 fe 14 01 06 03 b0 00 06  <=  4th key allocated
	 * 01 f0 00 07 03 b0 00 07     <=  5th key unallocated
	 * ...
	 * 01 f0 00 0c 03 b0 00 0c     <= 10th key unallocated
	 * For allocated keys, the fourth byte seems to indicate the
	 * default key and the fifth byte indicates the key_ref of
	 * the private key.
	 */
	ind = 2; /* skip length */
	while (ibuf[ind] == 0x01) {
		if (ibuf[ind+1] == 0xFE) {
			gemsafe_prkeys[i].ref = ibuf[ind+4];
			sc_log(card->ctx, "Key container %d is allocated and uses key_ref %d",
					i+1, gemsafe_prkeys[i].ref);
			ind += 9;
		}
		else {
			gemsafe_prkeys[i].label = NULL;
			gemsafe_cert[i].label = NULL;
			sc_log(card->ctx, "Key container %d is unallocated", i+1);
			ind += 8;
		}
		i++;
	}

	/* Delete additional key containers from the data structures if
	 * this card can't accommodate them.
	 */
	for (; i < gemsafe_cert_max; i++) {
		gemsafe_prkeys[i].label = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -208,7 +208,7 @@
 	 * the private key.
 	 */
 	ind = 2; /* skip length */
-	while (ibuf[ind] == 0x01) {
+	while (ibuf[ind] == 0x01 && i < gemsafe_cert_max) {
 		if (ibuf[ind+1] == 0xFE) {
 			gemsafe_prkeys[i].ref = ibuf[ind+4];
 			sc_log(card->ctx, "Key container %d is allocated and uses key_ref %d",
```
