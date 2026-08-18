# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2672_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2672_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2515-2555 of the vulnerable file.

        /* first lets see if we know the TLVs name*/
	ND_PRINT((ndo, "\n\t    %s TLV #%u, length: %u",
               tok2str(isis_tlv_values,
                       "unknown",
                       tlv_type),
               tlv_type,
               tlv_len));

        if (tlv_len == 0) /* something is invalid */
	    continue;

	if (packet_len < tlv_len)
	    goto trunc;

        /* now check if we have a decoder otherwise do a hexdump at the end*/
	switch (tlv_type) {
	case ISIS_TLV_AREA_ADDR:
	    ND_TCHECK2(*tptr, 1);
	    alen = *tptr++;
	    while (tmp && alen < tmp) {
		ND_PRINT((ndo, "\n\t      Area address (length: %u): %s",
                       alen,
                       isonsap_string(ndo, tptr, alen)));
		tptr += alen;
		tmp -= alen + 1;
		if (tmp==0) /* if this is the last area address do not attemt a boundary check */
                    break;
		ND_TCHECK2(*tptr, 1);
		alen = *tptr++;
	    }
	    break;
	case ISIS_TLV_ISNEIGH:
	    while (tmp >= ETHER_ADDR_LEN) {
                ND_TCHECK2(*tptr, ETHER_ADDR_LEN);
                ND_PRINT((ndo, "\n\t      SNPA: %s", isis_print_id(tptr, ETHER_ADDR_LEN)));
                tmp -= ETHER_ADDR_LEN;
                tptr += ETHER_ADDR_LEN;
	    }
	    break;

        case ISIS_TLV_ISNEIGH_VARLEN:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2532,6 +2532,7 @@
 	    ND_TCHECK2(*tptr, 1);
 	    alen = *tptr++;
 	    while (tmp && alen < tmp) {
+	        ND_TCHECK2(*tptr, alen);
 		ND_PRINT((ndo, "\n\t      Area address (length: %u): %s",
                        alen,
                        isonsap_string(ndo, tptr, alen)));
```
