# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5115_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5115_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 118-158 of the vulnerable file.


	case 1: /* DLT_EN10MB */
		capture_eth(pd, hdrlen, len, ld);
		return;

	default:
		break;
	}

	ld->other++;
}

static void
dissect_pktap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *pktap_tree = NULL;
	proto_item *ti = NULL;
	tvbuff_t *next_tvb;
	int offset = 0;
	guint32 pkt_len, rectype, dlt;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKTAP");
	col_clear(pinfo->cinfo, COL_INFO);

	pkt_len = tvb_get_letohl(tvb, offset);
	col_add_fstr(pinfo->cinfo, COL_INFO, "PKTAP, %u byte header", pkt_len);

	/* Dissect the packet */
	ti = proto_tree_add_item(tree, proto_pktap, tvb, offset, pkt_len, ENC_NA);
	pktap_tree = proto_item_add_subtree(ti, ett_pktap);

	proto_tree_add_item(pktap_tree, hf_pktap_hdrlen, tvb, offset, 4,
	    ENC_LITTLE_ENDIAN);
	if (pkt_len < MIN_PKTAP_HDR_LEN) {
		proto_tree_add_expert(tree, pinfo, &ei_pktap_hdrlen_too_short,
		    tvb, offset, 4);
		return;
	}
	offset += 4;

	proto_tree_add_item(pktap_tree, hf_pktap_rectype, tvb, offset, 4,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -135,6 +135,9 @@
 	tvbuff_t *next_tvb;
 	int offset = 0;
 	guint32 pkt_len, rectype, dlt;
+	int wtap_encap;
+	struct eth_phdr eth;
+	void *phdr;
 
 	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKTAP");
 	col_clear(pinfo->cinfo, COL_INFO);
@@ -202,8 +205,20 @@
 
 	if (rectype == PKT_REC_PACKET) {
 		next_tvb = tvb_new_subset_remaining(tvb, pkt_len);
-		dissector_try_uint(wtap_encap_dissector_table,
-		    wtap_pcap_encap_to_wtap_encap(dlt), next_tvb, pinfo, tree);
+		wtap_encap = wtap_pcap_encap_to_wtap_encap(dlt);
+		switch (wtap_encap) {
+
+		case WTAP_ENCAP_ETHERNET:
+			eth.fcs_len = -1;    /* Unknown whether we have an FCS */
+			phdr = &eth;
+			break;
+
+		default:
+			phdr = NULL;
+			break;
+		}
+		dissector_try_uint_new(wtap_encap_dissector_table,
+		    wtap_encap, next_tvb, pinfo, tree, TRUE, phdr);
 	}
 }
 
```
