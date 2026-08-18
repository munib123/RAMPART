# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2644_6
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2644_6`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 653-694 of the vulnerable file.

struct isis_psnp_header {
    uint8_t pdu_len[2];
    uint8_t source_id[NODE_ID_LEN];
};

struct isis_tlv_lsp {
    uint8_t remaining_lifetime[2];
    uint8_t lsp_id[LSP_ID_LEN];
    uint8_t sequence_number[4];
    uint8_t checksum[2];
};

#define ISIS_COMMON_HEADER_SIZE (sizeof(struct isis_common_header))
#define ISIS_IIH_LAN_HEADER_SIZE (sizeof(struct isis_iih_lan_header))
#define ISIS_IIH_PTP_HEADER_SIZE (sizeof(struct isis_iih_ptp_header))
#define ISIS_LSP_HEADER_SIZE (sizeof(struct isis_lsp_header))
#define ISIS_CSNP_HEADER_SIZE (sizeof(struct isis_csnp_header))
#define ISIS_PSNP_HEADER_SIZE (sizeof(struct isis_psnp_header))

void
isoclns_print(netdissect_options *ndo,
              const uint8_t *p, u_int length, u_int caplen)
{
	if (caplen <= 1) { /* enough bytes on the wire ? */
		ND_PRINT((ndo, "|OSI"));
		return;
	}

	if (ndo->ndo_eflag)
		ND_PRINT((ndo, "OSI NLPID %s (0x%02x): ", tok2str(nlpid_values, "Unknown", *p), *p));

	switch (*p) {

	case NLPID_CLNP:
		if (!clnp_print(ndo, p, length))
			print_unknown_data(ndo, p, "\n\t", caplen);
		break;

	case NLPID_ESIS:
		esis_print(ndo, p, length);
		return;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -670,10 +670,9 @@
 #define ISIS_PSNP_HEADER_SIZE (sizeof(struct isis_psnp_header))
 
 void
-isoclns_print(netdissect_options *ndo,
-              const uint8_t *p, u_int length, u_int caplen)
+isoclns_print(netdissect_options *ndo, const uint8_t *p, u_int length)
 {
-	if (caplen <= 1) { /* enough bytes on the wire ? */
+	if (!ND_TTEST(*p)) { /* enough bytes on the wire ? */
 		ND_PRINT((ndo, "|OSI"));
 		return;
 	}
@@ -685,7 +684,7 @@
 
 	case NLPID_CLNP:
 		if (!clnp_print(ndo, p, length))
-			print_unknown_data(ndo, p, "\n\t", caplen);
+			print_unknown_data(ndo, p, "\n\t", length);
 		break;
 
 	case NLPID_ESIS:
@@ -694,7 +693,7 @@
 
 	case NLPID_ISIS:
 		if (!isis_print(ndo, p, length))
-			print_unknown_data(ndo, p, "\n\t", caplen);
+			print_unknown_data(ndo, p, "\n\t", length);
 		break;
 
 	case NLPID_NULLNS:
@@ -721,8 +720,8 @@
 		if (!ndo->ndo_eflag)
 			ND_PRINT((ndo, "OSI NLPID 0x%02x unknown", *p));
 		ND_PRINT((ndo, "%slength: %u", ndo->ndo_eflag ? "" : ", ", length));
-		if (caplen > 1)
-			print_unknown_data(ndo, p, "\n\t", caplen);
+		if (length > 1)
+			print_unknown_data(ndo, p, "\n\t", length);
 		break;
 	}
 }
```
