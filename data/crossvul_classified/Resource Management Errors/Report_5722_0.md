# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5722_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5722_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1076-1116 of the vulnerable file.

	/* There is not enough support do UPD LSO,
	 * so follow normal path
	 */
	kfree_skb(skb);

	return err;
}

static inline struct ipv6_opt_hdr *ip6_opt_dup(struct ipv6_opt_hdr *src,
					       gfp_t gfp)
{
	return src ? kmemdup(src, (src->hdrlen + 1) * 8, gfp) : NULL;
}

static inline struct ipv6_rt_hdr *ip6_rthdr_dup(struct ipv6_rt_hdr *src,
						gfp_t gfp)
{
	return src ? kmemdup(src, (src->hdrlen + 1) * 8, gfp) : NULL;
}

static void ip6_append_data_mtu(int *mtu,
				int *maxfraglen,
				unsigned int fragheaderlen,
				struct sk_buff *skb,
				struct rt6_info *rt)
{
	if (!(rt->dst.flags & DST_XFRM_TUNNEL)) {
		if (skb == NULL) {
			/* first fragment, reserve header_len */
			*mtu = *mtu - rt->dst.header_len;

		} else {
			/*
			 * this fragment is not first, the headers
			 * space is regarded as data space.
			 */
			*mtu = dst_mtu(rt->dst.path);
		}
		*maxfraglen = ((*mtu - fragheaderlen) & ~7)
			      + fragheaderlen - sizeof(struct frag_hdr);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1093,11 +1093,12 @@
 	return src ? kmemdup(src, (src->hdrlen + 1) * 8, gfp) : NULL;
 }
 
-static void ip6_append_data_mtu(int *mtu,
+static void ip6_append_data_mtu(unsigned int *mtu,
 				int *maxfraglen,
 				unsigned int fragheaderlen,
 				struct sk_buff *skb,
-				struct rt6_info *rt)
+				struct rt6_info *rt,
+				bool pmtuprobe)
 {
 	if (!(rt->dst.flags & DST_XFRM_TUNNEL)) {
 		if (skb == NULL) {
@@ -1109,7 +1110,9 @@
 			 * this fragment is not first, the headers
 			 * space is regarded as data space.
 			 */
-			*mtu = dst_mtu(rt->dst.path);
+			*mtu = min(*mtu, pmtuprobe ?
+				   rt->dst.dev->mtu :
+				   dst_mtu(rt->dst.path));
 		}
 		*maxfraglen = ((*mtu - fragheaderlen) & ~7)
 			      + fragheaderlen - sizeof(struct frag_hdr);
@@ -1126,11 +1129,10 @@
 	struct ipv6_pinfo *np = inet6_sk(sk);
 	struct inet_cork *cork;
 	struct sk_buff *skb, *skb_prev = NULL;
-	unsigned int maxfraglen, fragheaderlen;
+	unsigned int maxfraglen, fragheaderlen, mtu;
 	int exthdrlen;
 	int dst_exthdrlen;
 	int hh_len;
-	int mtu;
 	int copy;
 	int err;
 	int offset = 0;
@@ -1287,7 +1289,9 @@
 			/* update mtu and maxfraglen if necessary */
 			if (skb == NULL || skb_prev == NULL)
 				ip6_append_data_mtu(&mtu, &maxfraglen,
-						    fragheaderlen, skb, rt);
+						    fragheaderlen, skb, rt,
+						    np->pmtudisc ==
+						    IPV6_PMTUDISC_PROBE);
 
 			skb_prev = skb;
 
```
