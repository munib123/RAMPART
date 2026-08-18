# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5021_4
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5021_4`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 150-190 of the vulnerable file.

	inet->inet_dport = usin->sin6_port;

	/*
	 *	Check for a route to destination an obtain the
	 *	destination cache for it.
	 */

	fl6.flowi6_proto = sk->sk_protocol;
	fl6.daddr = sk->sk_v6_daddr;
	fl6.saddr = np->saddr;
	fl6.flowi6_oif = sk->sk_bound_dev_if;
	fl6.flowi6_mark = sk->sk_mark;
	fl6.fl6_dport = inet->inet_dport;
	fl6.fl6_sport = inet->inet_sport;

	if (!fl6.flowi6_oif && (addr_type&IPV6_ADDR_MULTICAST))
		fl6.flowi6_oif = np->mcast_oif;

	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

	opt = flowlabel ? flowlabel->opt : np->opt;
	final_p = fl6_update_dst(&fl6, opt, &final);

	dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
	err = 0;
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		goto out;
	}

	/* source address lookup done in ip6_dst_lookup */

	if (ipv6_addr_any(&np->saddr))
		np->saddr = fl6.saddr;

	if (ipv6_addr_any(&sk->sk_v6_rcv_saddr)) {
		sk->sk_v6_rcv_saddr = fl6.saddr;
		inet->inet_rcv_saddr = LOOPBACK4_IPV6;
		if (sk->sk_prot->rehash)
			sk->sk_prot->rehash(sk);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -167,8 +167,10 @@
 
 	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));
 
-	opt = flowlabel ? flowlabel->opt : np->opt;
+	rcu_read_lock();
+	opt = flowlabel ? flowlabel->opt : rcu_dereference(np->opt);
 	final_p = fl6_update_dst(&fl6, opt, &final);
+	rcu_read_unlock();
 
 	dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
 	err = 0;
```
