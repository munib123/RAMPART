# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5764_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5764_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 73-113 of the vulnerable file.

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss);

		segs = NULL;
		goto out;
	}

	if (skb->encapsulation && skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL)
		segs = skb_udp_tunnel_segment(skb, features);
	else {
		/* Do software UFO. Complete and fill in the UDP checksum as HW cannot
		 * do checksum of UDP packets sent as multiple IP fragments.
		 */
		offset = skb_checksum_start_offset(skb);
		csum = skb_checksum(skb, offset, skb->len - offset, 0);
		offset += skb->csum_offset;
		*(__sum16 *)(skb->data + offset) = csum_fold(csum);
		skb->ip_summed = CHECKSUM_NONE;

		/* Check if there is enough headroom to insert fragment header. */
		tnl_hlen = skb_tnl_header_len(skb);
		if (skb_headroom(skb) < (tnl_hlen + frag_hdr_sz)) {
			if (gso_pskb_expand_head(skb, tnl_hlen + frag_hdr_sz))
				goto out;
		}

		/* Find the unfragmentable header and shift it left by frag_hdr_sz
		 * bytes to insert fragment header.
		 */
		unfrag_ip6hlen = ip6_find_1stfragopt(skb, &prevhdr);
		nexthdr = *prevhdr;
		*prevhdr = NEXTHDR_FRAGMENT;
		unfrag_len = (skb_network_header(skb) - skb_mac_header(skb)) +
			     unfrag_ip6hlen + tnl_hlen;
		packet_start = (u8 *) skb->head + SKB_GSO_CB(skb)->mac_offset;
		memmove(packet_start-frag_hdr_sz, packet_start, unfrag_len);

		SKB_GSO_CB(skb)->mac_offset -= frag_hdr_sz;
		skb->mac_header -= frag_hdr_sz;
		skb->network_header -= frag_hdr_sz;

		fptr = (struct frag_hdr *)(skb_network_header(skb) + unfrag_ip6hlen);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,7 +90,7 @@
 
 		/* Check if there is enough headroom to insert fragment header. */
 		tnl_hlen = skb_tnl_header_len(skb);
-		if (skb_headroom(skb) < (tnl_hlen + frag_hdr_sz)) {
+		if (skb->mac_header < (tnl_hlen + frag_hdr_sz)) {
 			if (gso_pskb_expand_head(skb, tnl_hlen + frag_hdr_sz))
 				goto out;
 		}
```
