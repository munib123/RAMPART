# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4841_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4841_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 234-275 of the vulnerable file.


	while ((skb = __skb_dequeue_tail(&sk->sk_write_queue)) != NULL)
		kfree_skb(skb);

	if (tunnel) {
		l2tp_tunnel_closeall(tunnel);
		sock_put(sk);
	}

	sk_refcnt_debug_dec(sk);
}

static int l2tp_ip_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_l2tpip *addr = (struct sockaddr_l2tpip *) uaddr;
	struct net *net = sock_net(sk);
	int ret;
	int chk_addr_ret;

	if (!sock_flag(sk, SOCK_ZAPPED))
		return -EINVAL;
	if (addr_len < sizeof(struct sockaddr_l2tpip))
		return -EINVAL;
	if (addr->l2tp_family != AF_INET)
		return -EINVAL;

	ret = -EADDRINUSE;
	read_lock_bh(&l2tp_ip_lock);
	if (__l2tp_ip_bind_lookup(net, addr->l2tp_addr.s_addr,
				  sk->sk_bound_dev_if, addr->l2tp_conn_id))
		goto out_in_use;

	read_unlock_bh(&l2tp_ip_lock);

	lock_sock(sk);
	if (sk->sk_state != TCP_CLOSE || addr_len < sizeof(struct sockaddr_l2tpip))
		goto out;

	chk_addr_ret = inet_addr_type(net, addr->l2tp_addr.s_addr);
	ret = -EADDRNOTAVAIL;
	if (addr->l2tp_addr.s_addr && chk_addr_ret != RTN_LOCAL &&
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -251,8 +251,6 @@
 	int ret;
 	int chk_addr_ret;
 
-	if (!sock_flag(sk, SOCK_ZAPPED))
-		return -EINVAL;
 	if (addr_len < sizeof(struct sockaddr_l2tpip))
 		return -EINVAL;
 	if (addr->l2tp_family != AF_INET)
@@ -267,6 +265,9 @@
 	read_unlock_bh(&l2tp_ip_lock);
 
 	lock_sock(sk);
+	if (!sock_flag(sk, SOCK_ZAPPED))
+		goto out;
+
 	if (sk->sk_state != TCP_CLOSE || addr_len < sizeof(struct sockaddr_l2tpip))
 		goto out;
 
```
