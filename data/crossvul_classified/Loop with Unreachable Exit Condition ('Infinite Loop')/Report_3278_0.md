# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 3278_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3278_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 61-101 of the vulnerable file.

	skb_shinfo(skb)->ip6_frag_id = htonl(id);
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
	unsigned int packet_len = skb_tail_pointer(skb) -
		skb_network_header(skb);
	int found_rhdr = 0;
	*nexthdr = &ipv6_hdr(skb)->nexthdr;

	while (offset <= packet_len) {
		struct ipv6_opt_hdr *exthdr;

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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,7 @@
 
 int ip6_find_1stfragopt(struct sk_buff *skb, u8 **nexthdr)
 {
-	u16 offset = sizeof(struct ipv6hdr);
+	unsigned int offset = sizeof(struct ipv6hdr);
 	unsigned int packet_len = skb_tail_pointer(skb) -
 		skb_network_header(skb);
 	int found_rhdr = 0;
@@ -86,6 +86,7 @@
 
 	while (offset <= packet_len) {
 		struct ipv6_opt_hdr *exthdr;
+		unsigned int len;
 
 		switch (**nexthdr) {
 
@@ -111,7 +112,10 @@
 
 		exthdr = (struct ipv6_opt_hdr *)(skb_network_header(skb) +
 						 offset);
-		offset += ipv6_optlen(exthdr);
+		len = ipv6_optlen(exthdr);
+		if (len + offset >= IPV6_MAXPLEN)
+			return -EINVAL;
+		offset += len;
 		*nexthdr = &exthdr->nexthdr;
 	}
 
```
