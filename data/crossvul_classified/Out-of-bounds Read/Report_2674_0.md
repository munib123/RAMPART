# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2674_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2674_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 21-64 of the vulnerable file.

 */

/* \summary: IEEE 802.15.4 printer */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include "netdissect.h"
#include "addrtoname.h"

#include "extract.h"

static const char *ftypes[] = {
	"Beacon",			/* 0 */
	"Data",				/* 1 */
	"ACK",				/* 2 */
	"Command",			/* 3 */
	"Reserved",			/* 4 */
	"Reserved",			/* 5 */
	"Reserved",			/* 6 */
	"Reserved",			/* 7 */
};

static int
extract_header_length(uint16_t fc)
{
	int len = 0;

	switch ((fc >> 10) & 0x3) {
	case 0x00:
		if (fc & (1 << 6)) /* intra-PAN with none dest addr */
			return -1;
		break;
	case 0x01:
		return -1;
	case 0x02:
		len += 4;
		break;
	case 0x03:
		len += 10;
		break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,144 +38,186 @@
 	"Data",				/* 1 */
 	"ACK",				/* 2 */
 	"Command",			/* 3 */
-	"Reserved",			/* 4 */
-	"Reserved",			/* 5 */
-	"Reserved",			/* 6 */
-	"Reserved",			/* 7 */
+	"Reserved (0x4)",		/* 4 */
+	"Reserved (0x5)",		/* 5 */
+	"Reserved (0x6)",		/* 6 */
+	"Reserved (0x7)",		/* 7 */
 };
 
-static int
-extract_header_length(uint16_t fc)
-{
-	int len = 0;
-
-	switch ((fc >> 10) & 0x3) {
-	case 0x00:
-		if (fc & (1 << 6)) /* intra-PAN with none dest addr */
-			return -1;
-		break;
-	case 0x01:
-		return -1;
-	case 0x02:
-		len += 4;
-		break;
-	case 0x03:
-		len += 10;
-		break;
-	}
-
-	switch ((fc >> 14) & 0x3) {
-	case 0x00:
-		break;
-	case 0x01:
-		return -1;
-	case 0x02:
-		len += 4;
-		break;
-	case 0x03:
-		len += 10;
-		break;
-	}
-
-	if (fc & (1 << 6)) {
-		if (len < 2)
-			return -1;
-		len -= 2;
-	}
-
-	return len;
-}
-
+/*
+ * Frame Control subfields.
+ */
+#define FC_FRAME_TYPE(fc)		((fc) & 0x7)
+#define FC_SECURITY_ENABLED		0x0008
+#define FC_FRAME_PENDING		0x0010
+#define FC_ACK_REQUEST			0x0020
+#define FC_PAN_ID_COMPRESSION		0x0040
+#define FC_DEST_ADDRESSING_MODE(fc)	(((fc) >> 10) & 0x3)
+#define FC_FRAME_VERSION(fc)		(((fc) >> 12) & 0x3)
+#define FC_SRC_ADDRESSING_MODE(fc)	(((fc) >> 14) & 0x3)
+
+#define FC_ADDRESSING_MODE_NONE		0x00
+#define FC_ADDRESSING_MODE_RESERVED	0x01
+#define FC_ADDRESSING_MODE_SHORT	0x02
+#define FC_ADDRESSING_MODE_LONG		0x03
 
 u_int
 ieee802_15_4_if_print(netdissect_options *ndo,
                       const struct pcap_pkthdr *h, const u_char *p)
 {
 	u_int caplen = h->caplen;
-	int hdrlen;
+	u_int hdrlen;
 	uint16_t fc;
 	uint8_t seq;
+	uint16_t panid = 0;
 
 	if (caplen < 3) {
-		ND_PRINT((ndo, "[|802.15.4] %x", caplen));
+		ND_PRINT((ndo, "[|802.15.4]"));
 		return caplen;
 	}
+	hdrlen = 3;
 
 	fc = EXTRACT_LE_16BITS(p);
-	hdrlen = extract_header_length(fc);
-
 	seq = EXTRACT_LE_8BITS(p + 2);
 
 	p += 3;
 	caplen -= 3;
 
-	ND_PRINT((ndo,"IEEE 802.15.4 %s packet ", ftypes[fc & 0x7]));
+	ND_PRINT((ndo,"IEEE 802.15.4 %s packet ", ftypes[FC_FRAME_TYPE(fc)]));
 	if (ndo->ndo_vflag)
 		ND_PRINT((ndo,"seq %02x ", seq));
-	if (hdrlen == -1) {
-		ND_PRINT((ndo,"invalid! "));
-		return caplen;
+
+	/*
+	 * Destination address and PAN ID, if present.
+	 */
+	switch (FC_DEST_ADDRESSING_MODE(fc)) {
+	case FC_ADDRESSING_MODE_NONE:
+		if (fc & FC_PAN_ID_COMPRESSION) {
+			/*
+			 * PAN ID compression; this requires that both
+			 * the source and destination addresses be present,
+			 * but the destination address is missing.
+			 */
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		if (ndo->ndo_vflag)
+			ND_PRINT((ndo,"none "));
+		break;
+	case FC_ADDRESSING_MODE_RESERVED:
+		if (ndo->ndo_vflag)
+			ND_PRINT((ndo,"reserved destination addressing mode"));
+		return hdrlen;
+	case FC_ADDRESSING_MODE_SHORT:
+		if (caplen < 2) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		panid = EXTRACT_LE_16BITS(p);
+		p += 2;
+		caplen -= 2;
+		hdrlen += 2;
+		if (caplen < 2) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		if (ndo->ndo_vflag)
+			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p + 2)));
+		p += 2;
+		caplen -= 2;
+		hdrlen += 2;
+		break;
+	case FC_ADDRESSING_MODE_LONG:
+		if (caplen < 2) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		panid = EXTRACT_LE_16BITS(p);
+		p += 2;
+		caplen -= 2;
+		hdrlen += 2;
+		if (caplen < 8) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		if (ndo->ndo_vflag)
+			ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p + 2)));
+		p += 8;
+		caplen -= 8;
+		hdrlen += 8;
+		break;
 	}
-
-
-	if (!ndo->ndo_vflag) {
-		p+= hdrlen;
-		caplen -= hdrlen;
-	} else {
-		uint16_t panid = 0;
-
-		switch ((fc >> 10) & 0x3) {
-		case 0x00:
+	if (ndo->ndo_vflag)
+		ND_PRINT((ndo,"< "));
+
+	/*
+	 * Source address and PAN ID, if present.
+	 */
+	switch (FC_SRC_ADDRESSING_MODE(fc)) {
+	case FC_ADDRESSING_MODE_NONE:
+		if (ndo->ndo_vflag)
 			ND_PRINT((ndo,"none "));
-			break;
-		case 0x01:
-			ND_PRINT((ndo,"reserved destination addressing mode"));
-			return 0;
-		case 0x02:
+		break;
+	case FC_ADDRESSING_MODE_RESERVED:
+		if (ndo->ndo_vflag)
+			ND_PRINT((ndo,"reserved source addressing mode"));
+		return 0;
+	case FC_ADDRESSING_MODE_SHORT:
+		if (!(fc & FC_PAN_ID_COMPRESSION)) {
+			/*
+			 * The source PAN ID is not compressed out, so
+			 * fetch it.  (Otherwise, we'll use the destination
+			 * PAN ID, fetched above.)
+			 */
+			if (caplen < 2) {
+				ND_PRINT((ndo, "[|802.15.4]"));
+				return hdrlen;
+			}
 			panid = EXTRACT_LE_16BITS(p);
 			p += 2;
+			caplen -= 2;
+			hdrlen += 2;
+		}
+		if (caplen < 2) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		if (ndo->ndo_vflag)
 			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p)));
-			p += 2;
-			break;
-		case 0x03:
+		p += 2;
+		caplen -= 2;
+		hdrlen += 2;
+		break;
+	case FC_ADDRESSING_MODE_LONG:
+		if (!(fc & FC_PAN_ID_COMPRESSION)) {
+			/*
+			 * The source PAN ID is not compressed out, so
+			 * fetch it.  (Otherwise, we'll use the destination
+			 * PAN ID, fetched above.)
+			 */
+			if (caplen < 2) {
+				ND_PRINT((ndo, "[|802.15.4]"));
+				return hdrlen;
+			}
 			panid = EXTRACT_LE_16BITS(p);
 			p += 2;
+			caplen -= 2;
+			hdrlen += 2;
+		}
+		if (caplen < 8) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		if (ndo->ndo_vflag)
 			ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p)));
-			p += 8;
-			break;
-		}
-		ND_PRINT((ndo,"< "));
-
-		switch ((fc >> 14) & 0x3) {
-		case 0x00:
-			ND_PRINT((ndo,"none "));
-			break;
-		case 0x01:
-			ND_PRINT((ndo,"reserved source addressing mode"));
-			return 0;
-		case 0x02:
-			if (!(fc & (1 << 6))) {
-				panid = EXTRACT_LE_16BITS(p);
-				p += 2;
-			}
-			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p)));
-			p += 2;
-			break;
-		case 0x03:
-			if (!(fc & (1 << 6))) {
-				panid = EXTRACT_LE_16BITS(p);
-				p += 2;
-			}
-                        ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p)));
-			p += 8;
-			break;
-		}
-
-		caplen -= hdrlen;
+		p += 8;
+		caplen -= 8;
+		hdrlen += 8;
+		break;
 	}
 
 	if (!ndo->ndo_suppress_default_print)
 		ND_DEFAULTPRINT(p, caplen);
 
-	return 0;
+	return hdrlen;
 }
```
