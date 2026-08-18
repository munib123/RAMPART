# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5021_5
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5021_5`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 710-750 of the vulnerable file.

		ipv6_push_exthdr(skb, proto, NEXTHDR_DEST, opt->dst1opt);
}

struct ipv6_txoptions *
ipv6_dup_options(struct sock *sk, struct ipv6_txoptions *opt)
{
	struct ipv6_txoptions *opt2;

	opt2 = sock_kmalloc(sk, opt->tot_len, GFP_ATOMIC);
	if (opt2) {
		long dif = (char *)opt2 - (char *)opt;
		memcpy(opt2, opt, opt->tot_len);
		if (opt2->hopopt)
			*((char **)&opt2->hopopt) += dif;
		if (opt2->dst0opt)
			*((char **)&opt2->dst0opt) += dif;
		if (opt2->dst1opt)
			*((char **)&opt2->dst1opt) += dif;
		if (opt2->srcrt)
			*((char **)&opt2->srcrt) += dif;
	}
	return opt2;
}
EXPORT_SYMBOL_GPL(ipv6_dup_options);

static int ipv6_renew_option(void *ohdr,
			     struct ipv6_opt_hdr __user *newopt, int newoptlen,
			     int inherit,
			     struct ipv6_opt_hdr **hdr,
			     char **p)
{
	if (inherit) {
		if (ohdr) {
			memcpy(*p, ohdr, ipv6_optlen((struct ipv6_opt_hdr *)ohdr));
			*hdr = (struct ipv6_opt_hdr *)*p;
			*p += CMSG_ALIGN(ipv6_optlen(*hdr));
		}
	} else {
		if (newopt) {
			if (copy_from_user(*p, newopt, newoptlen))
				return -EFAULT;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -727,6 +727,7 @@
 			*((char **)&opt2->dst1opt) += dif;
 		if (opt2->srcrt)
 			*((char **)&opt2->srcrt) += dif;
+		atomic_set(&opt2->refcnt, 1);
 	}
 	return opt2;
 }
@@ -790,7 +791,7 @@
 		return ERR_PTR(-ENOBUFS);
 
 	memset(opt2, 0, tot_len);
-
+	atomic_set(&opt2->refcnt, 1);
 	opt2->tot_len = tot_len;
 	p = (char *)(opt2 + 1);
 
```
