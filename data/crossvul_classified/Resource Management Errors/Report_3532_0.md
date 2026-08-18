# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3532_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3532_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1318-1358 of the vulnerable file.

		if (unlikely(type & ~(SKB_GSO_UDP | SKB_GSO_DODGY) ||
			     !(type & (SKB_GSO_UDP))))
			goto out;

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss);

		segs = NULL;
		goto out;
	}

	/* Do software UFO. Complete and fill in the UDP checksum as HW cannot
	 * do checksum of UDP packets sent as multiple IP fragments.
	 */
	offset = skb->csum_start - skb_headroom(skb);
	csum = skb_checksum(skb, offset, skb->len- offset, 0);
	offset += skb->csum_offset;
	*(__sum16 *)(skb->data + offset) = csum_fold(csum);
	skb->ip_summed = CHECKSUM_NONE;

	/* Check if there is enough headroom to insert fragment header. */
	if ((skb_headroom(skb) < frag_hdr_sz) &&
	    pskb_expand_head(skb, frag_hdr_sz, 0, GFP_ATOMIC))
		goto out;

	/* Find the unfragmentable header and shift it left by frag_hdr_sz
	 * bytes to insert fragment header.
	 */
	unfrag_ip6hlen = ip6_find_1stfragopt(skb, &prevhdr);
	nexthdr = *prevhdr;
	*prevhdr = NEXTHDR_FRAGMENT;
	unfrag_len = skb_network_header(skb) - skb_mac_header(skb) +
		     unfrag_ip6hlen;
	mac_start = skb_mac_header(skb);
	memmove(mac_start-frag_hdr_sz, mac_start, unfrag_len);

	skb->mac_header -= frag_hdr_sz;
	skb->network_header -= frag_hdr_sz;

	fptr = (struct frag_hdr *)(skb_network_header(skb) + unfrag_ip6hlen);
	fptr->nexthdr = nexthdr;
	fptr->reserved = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1335,7 +1335,7 @@
 	skb->ip_summed = CHECKSUM_NONE;
 
 	/* Check if there is enough headroom to insert fragment header. */
-	if ((skb_headroom(skb) < frag_hdr_sz) &&
+	if ((skb_mac_header(skb) < skb->head + frag_hdr_sz) &&
 	    pskb_expand_head(skb, frag_hdr_sz, 0, GFP_ATOMIC))
 		goto out;
 
```
