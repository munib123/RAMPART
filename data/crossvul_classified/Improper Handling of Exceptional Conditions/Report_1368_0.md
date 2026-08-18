# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in c
**Pair ID:** 1368_0
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1368_0`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```c
Lines 301-341 of the vulnerable file.

struct fib6_table *fib6_new_table(struct net *net, u32 id)
{
	return fib6_get_table(net, id);
}

struct fib6_table *fib6_get_table(struct net *net, u32 id)
{
	  return net->ipv6.fib6_main_tbl;
}

struct dst_entry *fib6_rule_lookup(struct net *net, struct flowi6 *fl6,
				   const struct sk_buff *skb,
				   int flags, pol_lookup_t lookup)
{
	struct rt6_info *rt;

	rt = lookup(net, net->ipv6.fib6_main_tbl, fl6, skb, flags);
	if (rt->dst.error == -EAGAIN) {
		ip6_rt_put_flags(rt, flags);
		rt = net->ipv6.ip6_null_entry;
		if (!(flags | RT6_LOOKUP_F_DST_NOREF))
			dst_hold(&rt->dst);
	}

	return &rt->dst;
}

/* called with rcu lock held; no reference taken on fib6_info */
int fib6_lookup(struct net *net, int oif, struct flowi6 *fl6,
		struct fib6_result *res, int flags)
{
	return fib6_table_lookup(net, net->ipv6.fib6_main_tbl, oif, fl6,
				 res, flags);
}

static void __net_init fib6_tables_init(struct net *net)
{
	fib6_link_table(net, net->ipv6.fib6_main_tbl);
}

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -318,7 +318,7 @@
 	if (rt->dst.error == -EAGAIN) {
 		ip6_rt_put_flags(rt, flags);
 		rt = net->ipv6.ip6_null_entry;
-		if (!(flags | RT6_LOOKUP_F_DST_NOREF))
+		if (!(flags & RT6_LOOKUP_F_DST_NOREF))
 			dst_hold(&rt->dst);
 	}
 
```
