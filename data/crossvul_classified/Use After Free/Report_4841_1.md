# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4841_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4841_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 252-293 of the vulnerable file.

	release_sock(sk);

	if (tunnel) {
		l2tp_tunnel_closeall(tunnel);
		sock_put(sk);
	}

	inet6_destroy_sock(sk);
}

static int l2tp_ip6_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sockaddr_l2tpip6 *addr = (struct sockaddr_l2tpip6 *) uaddr;
	struct net *net = sock_net(sk);
	__be32 v4addr = 0;
	int addr_type;
	int err;

	if (!sock_flag(sk, SOCK_ZAPPED))
		return -EINVAL;
	if (addr->l2tp_family != AF_INET6)
		return -EINVAL;
	if (addr_len < sizeof(*addr))
		return -EINVAL;

	addr_type = ipv6_addr_type(&addr->l2tp_addr);

	/* l2tp_ip6 sockets are IPv6 only */
	if (addr_type == IPV6_ADDR_MAPPED)
		return -EADDRNOTAVAIL;

	/* L2TP is point-point, not multicast */
	if (addr_type & IPV6_ADDR_MULTICAST)
		return -EADDRNOTAVAIL;

	err = -EADDRINUSE;
	read_lock_bh(&l2tp_ip6_lock);
	if (__l2tp_ip6_bind_lookup(net, &addr->l2tp_addr,
				   sk->sk_bound_dev_if, addr->l2tp_conn_id))
		goto out_in_use;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -269,8 +269,6 @@
 	int addr_type;
 	int err;
 
-	if (!sock_flag(sk, SOCK_ZAPPED))
-		return -EINVAL;
 	if (addr->l2tp_family != AF_INET6)
 		return -EINVAL;
 	if (addr_len < sizeof(*addr))
@@ -296,6 +294,9 @@
 	lock_sock(sk);
 
 	err = -EINVAL;
+	if (!sock_flag(sk, SOCK_ZAPPED))
+		goto out_unlock;
+
 	if (sk->sk_state != TCP_CLOSE)
 		goto out_unlock;
 
```
