# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2124_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2124_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 583-623 of the vulnerable file.


	pr_err_once("Please fix %s, as pkt_type couldn't be found!\n", __func__);
	return -1;
}

static u64 __skb_get_pay_offset(u64 ctx, u64 A, u64 X, u64 r4, u64 r5)
{
	struct sk_buff *skb = (struct sk_buff *)(long) ctx;

	return __skb_get_poff(skb);
}

static u64 __skb_get_nlattr(u64 ctx, u64 A, u64 X, u64 r4, u64 r5)
{
	struct sk_buff *skb = (struct sk_buff *)(long) ctx;
	struct nlattr *nla;

	if (skb_is_nonlinear(skb))
		return 0;

	if (A > skb->len - sizeof(struct nlattr))
		return 0;

	nla = nla_find((struct nlattr *) &skb->data[A], skb->len - A, X);
	if (nla)
		return (void *) nla - (void *) skb->data;

	return 0;
}

static u64 __skb_get_nlattr_nest(u64 ctx, u64 A, u64 X, u64 r4, u64 r5)
{
	struct sk_buff *skb = (struct sk_buff *)(long) ctx;
	struct nlattr *nla;

	if (skb_is_nonlinear(skb))
		return 0;

	if (A > skb->len - sizeof(struct nlattr))
		return 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -600,6 +600,9 @@
 	if (skb_is_nonlinear(skb))
 		return 0;
 
+	if (skb->len < sizeof(struct nlattr))
+		return 0;
+
 	if (A > skb->len - sizeof(struct nlattr))
 		return 0;
 
@@ -618,11 +621,14 @@
 	if (skb_is_nonlinear(skb))
 		return 0;
 
+	if (skb->len < sizeof(struct nlattr))
+		return 0;
+
 	if (A > skb->len - sizeof(struct nlattr))
 		return 0;
 
 	nla = (struct nlattr *) &skb->data[A];
-	if (nla->nla_len > A - skb->len)
+	if (nla->nla_len > skb->len - A)
 		return 0;
 
 	nla = nla_find_nested(nla, X);
```
