# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5021_3
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5021_3`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 411-453 of the vulnerable file.

{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sk_buff *skb;
	struct ipv6_txoptions *opt;

	/* Release rx options */

	skb = xchg(&np->pktoptions, NULL);
	if (skb)
		kfree_skb(skb);

	skb = xchg(&np->rxpmtu, NULL);
	if (skb)
		kfree_skb(skb);

	/* Free flowlabels */
	fl6_free_socklist(sk);

	/* Free tx options */

	opt = xchg(&np->opt, NULL);
	if (opt)
		sock_kfree_s(sk, opt, opt->tot_len);
}
EXPORT_SYMBOL_GPL(inet6_destroy_sock);

/*
 *	This does both peername and sockname.
 */

int inet6_getname(struct socket *sock, struct sockaddr *uaddr,
		 int *uaddr_len, int peer)
{
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *)uaddr;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);

	sin->sin6_family = AF_INET6;
	sin->sin6_flowinfo = 0;
	sin->sin6_scope_id = 0;
	if (peer) {
		if (!inet->inet_dport)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -428,9 +428,11 @@
 
 	/* Free tx options */
 
-	opt = xchg(&np->opt, NULL);
-	if (opt)
-		sock_kfree_s(sk, opt, opt->tot_len);
+	opt = xchg((__force struct ipv6_txoptions **)&np->opt, NULL);
+	if (opt) {
+		atomic_sub(opt->tot_len, &sk->sk_omem_alloc);
+		txopt_put(opt);
+	}
 }
 EXPORT_SYMBOL_GPL(inet6_destroy_sock);
 
@@ -659,7 +661,10 @@
 		fl6.fl6_sport = inet->inet_sport;
 		security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));
 
-		final_p = fl6_update_dst(&fl6, np->opt, &final);
+		rcu_read_lock();
+		final_p = fl6_update_dst(&fl6, rcu_dereference(np->opt),
+					 &final);
+		rcu_read_unlock();
 
 		dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
 		if (IS_ERR(dst)) {
```
