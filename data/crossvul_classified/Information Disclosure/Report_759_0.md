# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 759_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `759_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 471-511 of the vulnerable file.

 * if one generator is seldom used. This makes hard for an attacker
 * to infer how many packets were sent between two points in time.
 */
u32 ip_idents_reserve(u32 hash, int segs)
{
	struct ip_ident_bucket *bucket = ip_idents + hash % IP_IDENTS_SZ;
	u32 old = ACCESS_ONCE(bucket->stamp32);
	u32 now = (u32)jiffies;
	u32 delta = 0;

	if (old != now && cmpxchg(&bucket->stamp32, old, now) == old)
		delta = prandom_u32_max(now - old);

	return atomic_add_return(segs + delta, &bucket->id) - segs;
}
EXPORT_SYMBOL(ip_idents_reserve);

void __ip_select_ident(struct iphdr *iph, int segs)
{
	static u32 ip_idents_hashrnd __read_mostly;
	u32 hash, id;

	net_get_random_once(&ip_idents_hashrnd, sizeof(ip_idents_hashrnd));

	hash = jhash_3words((__force u32)iph->daddr,
			    (__force u32)iph->saddr,
			    iph->protocol,
			    ip_idents_hashrnd);
	id = ip_idents_reserve(hash, segs);
	iph->id = htons(id);
}
EXPORT_SYMBOL(__ip_select_ident);

static void __build_flow_key(struct flowi4 *fl4, const struct sock *sk,
			     const struct iphdr *iph,
			     int oif, u8 tos,
			     u8 prot, u32 mark, int flow_flags)
{
	if (sk) {
		const struct inet_sock *inet = inet_sk(sk);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -488,13 +488,15 @@
 void __ip_select_ident(struct iphdr *iph, int segs)
 {
 	static u32 ip_idents_hashrnd __read_mostly;
+	static u32 ip_idents_hashrnd_extra __read_mostly;
 	u32 hash, id;
 
 	net_get_random_once(&ip_idents_hashrnd, sizeof(ip_idents_hashrnd));
+	net_get_random_once(&ip_idents_hashrnd_extra, sizeof(ip_idents_hashrnd_extra));
 
 	hash = jhash_3words((__force u32)iph->daddr,
 			    (__force u32)iph->saddr,
-			    iph->protocol,
+			    iph->protocol ^ ip_idents_hashrnd_extra,
 			    ip_idents_hashrnd);
 	id = ip_idents_reserve(hash, segs);
 	iph->id = htons(id);
```
