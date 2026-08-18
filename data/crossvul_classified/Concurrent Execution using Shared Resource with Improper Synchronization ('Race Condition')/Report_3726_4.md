# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3726_4
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3726_4`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 136-176 of the vulnerable file.

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_error_queue);

	sk_mem_reclaim(sk);

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != TCP_CLOSE) {
		pr_err("Attempt to release TCP socket in state %d %p\n",
		       sk->sk_state, sk);
		return;
	}
	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Attempt to release alive inet socket %p\n", sk);
		return;
	}

	WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	WARN_ON(atomic_read(&sk->sk_wmem_alloc));
	WARN_ON(sk->sk_wmem_queued);
	WARN_ON(sk->sk_forward_alloc);

	kfree(inet->opt);
	dst_release(rcu_dereference_check(sk->sk_dst_cache, 1));
	sk_refcnt_debug_dec(sk);
}
EXPORT_SYMBOL(inet_sock_destruct);

/*
 *	The routines beyond this point handle the behaviour of an AF_INET
 *	socket object. Mostly it punts to the subprotocols of IP to do
 *	the work.
 */

/*
 *	Automatically bind an unbound socket.
 */

static int inet_autobind(struct sock *sk)
{
	struct inet_sock *inet;
	/* We may need to bind the socket. */
	lock_sock(sk);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -153,7 +153,7 @@
 	WARN_ON(sk->sk_wmem_queued);
 	WARN_ON(sk->sk_forward_alloc);
 
-	kfree(inet->opt);
+	kfree(rcu_dereference_protected(inet->inet_opt, 1));
 	dst_release(rcu_dereference_check(sk->sk_dst_cache, 1));
 	sk_refcnt_debug_dec(sk);
 }
@@ -1106,9 +1106,12 @@
 	struct flowi4 fl4;
 	struct rtable *rt;
 	__be32 new_saddr;
-
-	if (inet->opt && inet->opt->srr)
-		daddr = inet->opt->faddr;
+	struct ip_options_rcu *inet_opt;
+
+	inet_opt = rcu_dereference_protected(inet->inet_opt,
+					     sock_owned_by_user(sk));
+	if (inet_opt && inet_opt->opt.srr)
+		daddr = inet_opt->opt.faddr;
 
 	/* Query new route. */
 	rt = ip_route_connect(&fl4, daddr, 0, RT_CONN_FLAGS(sk),
@@ -1148,6 +1151,7 @@
 	struct inet_sock *inet = inet_sk(sk);
 	struct rtable *rt = (struct rtable *)__sk_dst_check(sk, 0);
 	__be32 daddr;
+	struct ip_options_rcu *inet_opt;
 	int err;
 
 	/* Route is OK, nothing to do. */
@@ -1155,9 +1159,12 @@
 		return 0;
 
 	/* Reroute. */
+	rcu_read_lock();
+	inet_opt = rcu_dereference(inet->inet_opt);
 	daddr = inet->inet_daddr;
-	if (inet->opt && inet->opt->srr)
-		daddr = inet->opt->faddr;
+	if (inet_opt && inet_opt->opt.srr)
+		daddr = inet_opt->opt.faddr;
+	rcu_read_unlock();
 	rt = ip_route_output_ports(sock_net(sk), sk, daddr, inet->inet_saddr,
 				   inet->inet_dport, inet->inet_sport,
 				   sk->sk_protocol, RT_CONN_FLAGS(sk),
```
