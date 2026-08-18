# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5115_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5115_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 821-861 of the vulnerable file.

  case RPCAP_SAMP_FIRST_AFTER_N_MS:
    proto_item_append_text (ti, ": First after %d ms", value);
    break;
  default:
    break;
  }
  return offset;
}


static void
dissect_rpcap_packet (tvbuff_t *tvb, packet_info *pinfo, proto_tree *top_tree,
                      proto_tree *parent_tree, gint offset, proto_item *top_item)
{
  proto_tree *tree;
  proto_item *ti;
  nstime_t ts;
  tvbuff_t *new_tvb;
  guint caplen, len, frame_no;
  gint reported_length_remaining;

  ti = proto_tree_add_item (parent_tree, hf_packet, tvb, offset, 20, ENC_NA);
  tree = proto_item_add_subtree (ti, ett_packet);

  ts.secs = tvb_get_ntohl (tvb, offset);
  ts.nsecs = tvb_get_ntohl (tvb, offset + 4) * 1000;
  proto_tree_add_time(tree, hf_timestamp, tvb, offset, 8, &ts);
  offset += 8;

  caplen = tvb_get_ntohl (tvb, offset);
  ti = proto_tree_add_item (tree, hf_caplen, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  len = tvb_get_ntohl (tvb, offset);
  proto_tree_add_item (tree, hf_len, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  frame_no = tvb_get_ntohl (tvb, offset);
  proto_tree_add_item (tree, hf_npkt, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -838,6 +838,8 @@
   tvbuff_t *new_tvb;
   guint caplen, len, frame_no;
   gint reported_length_remaining;
+  struct eth_phdr eth;
+  void *phdr;
 
   ti = proto_tree_add_item (parent_tree, hf_packet, tvb, offset, 20, ENC_NA);
   tree = proto_item_add_subtree (ti, ett_packet);
@@ -874,7 +876,18 @@
 
   new_tvb = tvb_new_subset (tvb, offset, caplen, len);
   if (decode_content && linktype != WTAP_ENCAP_UNKNOWN) {
-    dissector_try_uint(wtap_encap_dissector_table, linktype, new_tvb, pinfo, top_tree);
+    switch (linktype) {
+
+    case WTAP_ENCAP_ETHERNET:
+      eth.fcs_len = -1;    /* Unknown whether we have an FCS */
+      phdr = &eth;
+      break;
+
+    default:
+      phdr = NULL;
+      break;
+    }
+    dissector_try_uint_new(wtap_encap_dissector_table, linktype, new_tvb, pinfo, top_tree, TRUE, phdr);
 
     if (!info_added) {
       /* Only indicate when not added before */
```
