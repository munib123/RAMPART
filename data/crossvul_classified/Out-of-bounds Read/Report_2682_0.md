# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2682_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2682_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 87-127 of the vulnerable file.

        }

	ND_PRINT((ndo, ", length %u: ", length));
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
u_int
pktap_if_print(netdissect_options *ndo,
               const struct pcap_pkthdr *h, const u_char *p)
{
	uint32_t dlt, hdrlen, rectype;
	u_int caplen = h->caplen;
	u_int length = h->len;
	if_printer printer;
	const pktap_header_t *hdr;

	if (caplen < sizeof(pktap_header_t) || length < sizeof(pktap_header_t)) {
		ND_PRINT((ndo, "[|pktap]"));
		return (0);
	}
	hdr = (const pktap_header_t *)p;
	dlt = EXTRACT_LE_32BITS(&hdr->pkt_dlt);
	hdrlen = EXTRACT_LE_32BITS(&hdr->pkt_len);
	if (hdrlen < sizeof(pktap_header_t)) {
		/*
		 * Claimed header length < structure length.
		 * XXX - does this just mean some fields aren't
		 * being supplied, or is it truly an error (i.e.,
		 * is the length supplied so that the header can
		 * be expanded in the future)?
		 */
		ND_PRINT((ndo, "[|pktap]"));
		return (0);
	}
	if (caplen < hdrlen || length < hdrlen) {
		ND_PRINT((ndo, "[|pktap]"));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,6 +104,7 @@
 	u_int length = h->len;
 	if_printer printer;
 	const pktap_header_t *hdr;
+	struct pcap_pkthdr nhdr;
 
 	if (caplen < sizeof(pktap_header_t) || length < sizeof(pktap_header_t)) {
 		ND_PRINT((ndo, "[|pktap]"));
@@ -144,7 +145,10 @@
 
 	case PKT_REC_PACKET:
 		if ((printer = lookup_printer(dlt)) != NULL) {
-			hdrlen += printer(ndo, h, p);
+			nhdr = *h;
+			nhdr.caplen = caplen;
+			nhdr.len = length;
+			hdrlen += printer(ndo, &nhdr, p);
 		} else {
 			if (!ndo->ndo_eflag)
 				pktap_header_print(ndo, (const u_char *)hdr,
```
