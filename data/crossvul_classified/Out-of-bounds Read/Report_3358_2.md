# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3358_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3358_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 62-103 of the vulnerable file.

}
EXPORT_SYMBOL_GPL(ipv6_proxy_select_ident);

__be32 ipv6_select_ident(struct net *net,
			 const struct in6_addr *daddr,
			 const struct in6_addr *saddr)
{
	static u32 ip6_idents_hashrnd __read_mostly;
	u32 id;

	net_get_random_once(&ip6_idents_hashrnd, sizeof(ip6_idents_hashrnd));

	id = __ipv6_select_ident(net, ip6_idents_hashrnd, daddr, saddr);
	return htonl(id);
}
EXPORT_SYMBOL(ipv6_select_ident);

int ip6_find_1stfragopt(struct sk_buff *skb, u8 **nexthdr)
{
	u16 offset = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr *exthdr =
				(struct ipv6_opt_hdr *)(ipv6_hdr(skb) + 1);
	unsigned int packet_len = skb_tail_pointer(skb) -
		skb_network_header(skb);
	int found_rhdr = 0;
	*nexthdr = &ipv6_hdr(skb)->nexthdr;

	while (offset + 1 <= packet_len) {

		switch (**nexthdr) {

		case NEXTHDR_HOP:
			break;
		case NEXTHDR_ROUTING:
			found_rhdr = 1;
			break;
		case NEXTHDR_DEST:
#if IS_ENABLED(CONFIG_IPV6_MIP6)
			if (ipv6_find_tlv(skb, offset, IPV6_TLV_HAO) >= 0)
				break;
#endif
			if (found_rhdr)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,14 +79,13 @@
 int ip6_find_1stfragopt(struct sk_buff *skb, u8 **nexthdr)
 {
 	u16 offset = sizeof(struct ipv6hdr);
-	struct ipv6_opt_hdr *exthdr =
-				(struct ipv6_opt_hdr *)(ipv6_hdr(skb) + 1);
 	unsigned int packet_len = skb_tail_pointer(skb) -
 		skb_network_header(skb);
 	int found_rhdr = 0;
 	*nexthdr = &ipv6_hdr(skb)->nexthdr;
 
-	while (offset + 1 <= packet_len) {
+	while (offset <= packet_len) {
+		struct ipv6_opt_hdr *exthdr;
 
 		switch (**nexthdr) {
 
@@ -107,13 +106,16 @@
 			return offset;
 		}
 
+		if (offset + sizeof(struct ipv6_opt_hdr) > packet_len)
+			return -EINVAL;
+
+		exthdr = (struct ipv6_opt_hdr *)(skb_network_header(skb) +
+						 offset);
 		offset += ipv6_optlen(exthdr);
 		*nexthdr = &exthdr->nexthdr;
-		exthdr = (struct ipv6_opt_hdr *)(skb_network_header(skb) +
-						 offset);
 	}
 
-	return offset;
+	return -EINVAL;
 }
 EXPORT_SYMBOL(ip6_find_1stfragopt);
 
```
