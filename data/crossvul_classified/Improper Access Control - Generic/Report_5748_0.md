# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5748_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5748_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 991-1031 of the vulnerable file.

	if (err)
		return ERR_PTR(err);
	if (final_dst)
		fl6->daddr = *final_dst;
	if (can_sleep)
		fl6->flowi6_flags |= FLOWI_FLAG_CAN_SLEEP;

	return xfrm_lookup(sock_net(sk), dst, flowi6_to_flowi(fl6), sk, 0);
}
EXPORT_SYMBOL_GPL(ip6_sk_dst_lookup_flow);

static inline int ip6_ufo_append_data(struct sock *sk,
			int getfrag(void *from, char *to, int offset, int len,
			int odd, struct sk_buff *skb),
			void *from, int length, int hh_len, int fragheaderlen,
			int transhdrlen, int mtu,unsigned int flags,
			struct rt6_info *rt)

{
	struct sk_buff *skb;
	int err;

	/* There is support for UDP large send offload by network
	 * device, so create one single skb packet containing complete
	 * udp datagram
	 */
	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL) {
		struct frag_hdr fhdr;

		skb = sock_alloc_send_skb(sk,
			hh_len + fragheaderlen + transhdrlen + 20,
			(flags & MSG_DONTWAIT), &err);
		if (skb == NULL)
			return err;

		/* reserve space for Hardware header */
		skb_reserve(skb, hh_len);

		/* create space for UDP/IP header */
		skb_put(skb,fragheaderlen + transhdrlen);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1008,6 +1008,7 @@
 
 {
 	struct sk_buff *skb;
+	struct frag_hdr fhdr;
 	int err;
 
 	/* There is support for UDP large send offload by network
@@ -1015,8 +1016,6 @@
 	 * udp datagram
 	 */
 	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL) {
-		struct frag_hdr fhdr;
-
 		skb = sock_alloc_send_skb(sk,
 			hh_len + fragheaderlen + transhdrlen + 20,
 			(flags & MSG_DONTWAIT), &err);
@@ -1036,20 +1035,24 @@
 		skb->transport_header = skb->network_header + fragheaderlen;
 
 		skb->protocol = htons(ETH_P_IPV6);
-		skb->ip_summed = CHECKSUM_PARTIAL;
 		skb->csum = 0;
 
-		/* Specify the length of each IPv6 datagram fragment.
-		 * It has to be a multiple of 8.
-		 */
-		skb_shinfo(skb)->gso_size = (mtu - fragheaderlen -
-					     sizeof(struct frag_hdr)) & ~7;
-		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
-		ipv6_select_ident(&fhdr, rt);
-		skb_shinfo(skb)->ip6_frag_id = fhdr.identification;
 		__skb_queue_tail(&sk->sk_write_queue, skb);
-	}
-
+	} else if (skb_is_gso(skb)) {
+		goto append;
+	}
+
+	skb->ip_summed = CHECKSUM_PARTIAL;
+	/* Specify the length of each IPv6 datagram fragment.
+	 * It has to be a multiple of 8.
+	 */
+	skb_shinfo(skb)->gso_size = (mtu - fragheaderlen -
+				     sizeof(struct frag_hdr)) & ~7;
+	skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
+	ipv6_select_ident(&fhdr, rt);
+	skb_shinfo(skb)->ip6_frag_id = fhdr.identification;
+
+append:
 	return skb_append_datato_frags(sk, skb, getfrag, from,
 				       (length - transhdrlen));
 }
```
