# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2437_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2437_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 69-109 of the vulnerable file.

	if (!inet->inet_saddr)
		inet->inet_saddr = fl4->saddr;	/* Update source address */
	if (!inet->inet_rcv_saddr) {
		inet->inet_rcv_saddr = fl4->saddr;
		if (sk->sk_prot->rehash)
			sk->sk_prot->rehash(sk);
	}
	inet->inet_daddr = fl4->daddr;
	inet->inet_dport = usin->sin_port;
	sk->sk_state = TCP_ESTABLISHED;
	inet->inet_id = jiffies;

	sk_dst_set(sk, &rt->dst);
	err = 0;
out:
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(ip4_datagram_connect);

void ip4_datagram_release_cb(struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct ip_options_rcu *inet_opt;
	__be32 daddr = inet->inet_daddr;
	struct flowi4 fl4;
	struct rtable *rt;

	if (! __sk_dst_get(sk) || __sk_dst_check(sk, 0))
		return;

	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	if (inet_opt && inet_opt->opt.srr)
		daddr = inet_opt->opt.faddr;
	rt = ip_route_output_ports(sock_net(sk), &fl4, sk, daddr,
				   inet->inet_saddr, inet->inet_dport,
				   inet->inet_sport, sk->sk_protocol,
				   RT_CONN_FLAGS(sk), sk->sk_bound_dev_if);
	if (!IS_ERR(rt))
		__sk_dst_set(sk, &rt->dst);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,18 +86,26 @@
 }
 EXPORT_SYMBOL(ip4_datagram_connect);
 
+/* Because UDP xmit path can manipulate sk_dst_cache without holding
+ * socket lock, we need to use sk_dst_set() here,
+ * even if we own the socket lock.
+ */
 void ip4_datagram_release_cb(struct sock *sk)
 {
 	const struct inet_sock *inet = inet_sk(sk);
 	const struct ip_options_rcu *inet_opt;
 	__be32 daddr = inet->inet_daddr;
+	struct dst_entry *dst;
 	struct flowi4 fl4;
 	struct rtable *rt;
 
-	if (! __sk_dst_get(sk) || __sk_dst_check(sk, 0))
+	rcu_read_lock();
+
+	dst = __sk_dst_get(sk);
+	if (!dst || !dst->obsolete || dst->ops->check(dst, 0)) {
+		rcu_read_unlock();
 		return;
-
-	rcu_read_lock();
+	}
 	inet_opt = rcu_dereference(inet->inet_opt);
 	if (inet_opt && inet_opt->opt.srr)
 		daddr = inet_opt->opt.faddr;
@@ -105,8 +113,10 @@
 				   inet->inet_saddr, inet->inet_dport,
 				   inet->inet_sport, sk->sk_protocol,
 				   RT_CONN_FLAGS(sk), sk->sk_bound_dev_if);
-	if (!IS_ERR(rt))
-		__sk_dst_set(sk, &rt->dst);
+
+	dst = !IS_ERR(rt) ? &rt->dst : NULL;
+	sk_dst_set(sk, dst);
+
 	rcu_read_unlock();
 }
 EXPORT_SYMBOL_GPL(ip4_datagram_release_cb);
```
