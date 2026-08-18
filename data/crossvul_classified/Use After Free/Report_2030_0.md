# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2030_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2030_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 2837-2877 of the vulnerable file.

EXPORT_SYMBOL_GPL(skb_pull_rcsum);

/**
 *	skb_segment - Perform protocol segmentation on skb.
 *	@head_skb: buffer to segment
 *	@features: features for the output path (see dev->features)
 *
 *	This function performs segmentation on the given skb.  It returns
 *	a pointer to the first in a list of new skbs for the segments.
 *	In case of error it returns ERR_PTR(err).
 */
struct sk_buff *skb_segment(struct sk_buff *head_skb,
			    netdev_features_t features)
{
	struct sk_buff *segs = NULL;
	struct sk_buff *tail = NULL;
	struct sk_buff *list_skb = skb_shinfo(head_skb)->frag_list;
	skb_frag_t *frag = skb_shinfo(head_skb)->frags;
	unsigned int mss = skb_shinfo(head_skb)->gso_size;
	unsigned int doffset = head_skb->data - skb_mac_header(head_skb);
	unsigned int offset = doffset;
	unsigned int tnl_hlen = skb_tnl_header_len(head_skb);
	unsigned int headroom;
	unsigned int len;
	__be16 proto;
	bool csum;
	int sg = !!(features & NETIF_F_SG);
	int nfrags = skb_shinfo(head_skb)->nr_frags;
	int err = -ENOMEM;
	int i = 0;
	int pos;

	proto = skb_network_protocol(head_skb);
	if (unlikely(!proto))
		return ERR_PTR(-EINVAL);

	csum = !!can_checksum_protocol(features, proto);
	__skb_push(head_skb, doffset);
	headroom = skb_headroom(head_skb);
	pos = skb_headlen(head_skb);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2854,6 +2854,7 @@
 	skb_frag_t *frag = skb_shinfo(head_skb)->frags;
 	unsigned int mss = skb_shinfo(head_skb)->gso_size;
 	unsigned int doffset = head_skb->data - skb_mac_header(head_skb);
+	struct sk_buff *frag_skb = head_skb;
 	unsigned int offset = doffset;
 	unsigned int tnl_hlen = skb_tnl_header_len(head_skb);
 	unsigned int headroom;
@@ -2898,6 +2899,7 @@
 			i = 0;
 			nfrags = skb_shinfo(list_skb)->nr_frags;
 			frag = skb_shinfo(list_skb)->frags;
+			frag_skb = list_skb;
 			pos += skb_headlen(list_skb);
 
 			while (pos < offset + len) {
@@ -2985,6 +2987,7 @@
 				i = 0;
 				nfrags = skb_shinfo(list_skb)->nr_frags;
 				frag = skb_shinfo(list_skb)->frags;
+				frag_skb = list_skb;
 
 				BUG_ON(!nfrags);
 
@@ -2998,6 +3001,9 @@
 					pos, mss);
 				goto err;
 			}
+
+			if (unlikely(skb_orphan_frags(frag_skb, GFP_ATOMIC)))
+				goto err;
 
 			*nskb_frag = *frag;
 			__skb_frag_ref(nskb_frag);
```
