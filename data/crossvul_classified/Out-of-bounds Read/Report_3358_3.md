# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3358_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3358_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 74-114 of the vulnerable file.

		skb->ip_summed = CHECKSUM_NONE;

		/* If there is no outer header we can fake a checksum offload
		 * due to the fact that we have already done the checksum in
		 * software prior to segmenting the frame.
		 */
		if (!skb->encap_hdr_csum)
			features |= NETIF_F_HW_CSUM;

		/* Check if there is enough headroom to insert fragment header. */
		tnl_hlen = skb_tnl_header_len(skb);
		if (skb->mac_header < (tnl_hlen + frag_hdr_sz)) {
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
		fptr->nexthdr = nexthdr;
		fptr->reserved = 0;
		if (!skb_shinfo(skb)->ip6_frag_id)
			ipv6_proxy_select_ident(dev_net(skb->dev), skb);
		fptr->identification = skb_shinfo(skb)->ip6_frag_id;

		/* Fragment the skb. ipv6 header and the remaining fields of the
		 * fragment header are updated in ipv6_gso_segment()
		 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,6 +91,8 @@
 		 * bytes to insert fragment header.
 		 */
 		unfrag_ip6hlen = ip6_find_1stfragopt(skb, &prevhdr);
+		if (unfrag_ip6hlen < 0)
+			return ERR_PTR(unfrag_ip6hlen);
 		nexthdr = *prevhdr;
 		*prevhdr = NEXTHDR_FRAGMENT;
 		unfrag_len = (skb_network_header(skb) - skb_mac_header(skb)) +
```
