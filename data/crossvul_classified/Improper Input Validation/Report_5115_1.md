# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5115_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5115_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 840-880 of the vulnerable file.

{
    proto_tree    *ppi_tree    = NULL, *ppi_flags_tree = NULL, *seg_tree = NULL, *ampdu_tree = NULL;
    proto_tree    *agg_tree    = NULL;
    proto_item    *ti          = NULL;
    tvbuff_t      *next_tvb;
    int            offset      = 0;
    guint          version, flags;
    gint           tot_len, data_len;
    guint          data_type;
    guint32        dlt;
    guint32        n_ext_flags = 0;
    guint32        ampdu_id    = 0;
    fragment_head *fd_head     = NULL;
    fragment_item *ft_fdh      = NULL;
    gint           mpdu_count  = 0;
    gchar         *mpdu_str;
    gboolean       first_mpdu  = TRUE;
    guint          last_frame  = 0;
    gint len_remain, /*pad_len = 0,*/ ampdu_len = 0;
    struct ieee_802_11_phdr phdr;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPI");
    col_clear(pinfo->cinfo, COL_INFO);

    version = tvb_get_guint8(tvb, offset);
    flags = tvb_get_guint8(tvb, offset + 1);

    tot_len = tvb_get_letohs(tvb, offset+2);
    dlt = tvb_get_letohl(tvb, offset+4);

    col_add_fstr(pinfo->cinfo, COL_INFO, "PPI version %u, %u bytes",
                 version, tot_len);

    /* Dissect the packet */
    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_ppi,
                                            tvb, 0, tot_len, "PPI version %u, %u bytes", version, tot_len);
        ppi_tree = proto_item_add_subtree(ti, ett_ppi_pph);
        proto_tree_add_item(ppi_tree, hf_ppi_head_version,
                            tvb, offset, 1, ENC_LITTLE_ENDIAN);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -857,6 +857,9 @@
     guint          last_frame  = 0;
     gint len_remain, /*pad_len = 0,*/ ampdu_len = 0;
     struct ieee_802_11_phdr phdr;
+    int            wtap_encap;
+    struct eth_phdr eth;
+    void          *phdrp;
 
     col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPI");
     col_clear(pinfo->cinfo, COL_INFO);
@@ -1137,8 +1140,20 @@
         call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo, tree, &phdr);
     } else {
         /* Everything else.  This will pass a NULL data argument. */
-        dissector_try_uint(wtap_encap_dissector_table,
-            wtap_pcap_encap_to_wtap_encap(dlt), next_tvb, pinfo, tree);
+        wtap_encap = wtap_pcap_encap_to_wtap_encap(dlt);
+        switch (wtap_encap) {
+
+        case WTAP_ENCAP_ETHERNET:
+            eth.fcs_len = -1;    /* Unknown whether we have an FCS */
+            phdrp = &eth;
+            break;
+
+        default:
+            phdrp = NULL;
+            break;
+        }
+        dissector_try_uint_new(wtap_encap_dissector_table,
+            wtap_encap, next_tvb, pinfo, tree, TRUE, phdrp);
     }
 }
 
```
