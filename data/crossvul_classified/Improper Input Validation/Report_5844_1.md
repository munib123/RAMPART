# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5844_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5844_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 813-854 of the vulnerable file.

		kfree(ipc.opt);
	if (!err) {
		icmp_out_count(sock_net(sk), user_icmph.type);
		return len;
	}
	return err;

do_confirm:
	dst_confirm(&rt->dst);
	if (!(msg->msg_flags & MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}

int ping_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		 size_t len, int noblock, int flags, int *addr_len)
{
	struct inet_sock *isk = inet_sk(sk);
	int family = sk->sk_family;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sk_buff *skb;
	int copied, err;

	pr_debug("ping_recvmsg(sk=%p,sk->num=%u)\n", isk, isk->inet_num);

	err = -EOPNOTSUPP;
	if (flags & MSG_OOB)
		goto out;

	if (addr_len) {
		if (family == AF_INET)
			*addr_len = sizeof(*sin);
		else if (family == AF_INET6 && addr_len)
			*addr_len = sizeof(*sin6);
	}

	if (flags & MSG_ERRQUEUE) {
		if (family == AF_INET) {
			return ip_recv_error(sk, msg, len);
#if IS_ENABLED(CONFIG_IPV6)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -830,8 +830,6 @@
 {
 	struct inet_sock *isk = inet_sk(sk);
 	int family = sk->sk_family;
-	struct sockaddr_in *sin;
-	struct sockaddr_in6 *sin6;
 	struct sk_buff *skb;
 	int copied, err;
 
@@ -840,13 +838,6 @@
 	err = -EOPNOTSUPP;
 	if (flags & MSG_OOB)
 		goto out;
-
-	if (addr_len) {
-		if (family == AF_INET)
-			*addr_len = sizeof(*sin);
-		else if (family == AF_INET6 && addr_len)
-			*addr_len = sizeof(*sin6);
-	}
 
 	if (flags & MSG_ERRQUEUE) {
 		if (family == AF_INET) {
@@ -877,11 +868,13 @@
 
 	/* Copy the address and add cmsg data. */
 	if (family == AF_INET) {
-		sin = (struct sockaddr_in *) msg->msg_name;
+		struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
+
 		sin->sin_family = AF_INET;
 		sin->sin_port = 0 /* skb->h.uh->source */;
 		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
 		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
+		*addr_len = sizeof(*sin);
 
 		if (isk->cmsg_flags)
 			ip_cmsg_recv(msg, skb);
@@ -890,17 +883,19 @@
 	} else if (family == AF_INET6) {
 		struct ipv6_pinfo *np = inet6_sk(sk);
 		struct ipv6hdr *ip6 = ipv6_hdr(skb);
-		sin6 = (struct sockaddr_in6 *) msg->msg_name;
+		struct sockaddr_in6 *sin6 =
+			(struct sockaddr_in6 *)msg->msg_name;
+
 		sin6->sin6_family = AF_INET6;
 		sin6->sin6_port = 0;
 		sin6->sin6_addr = ip6->saddr;
-
 		sin6->sin6_flowinfo = 0;
 		if (np->sndflow)
 			sin6->sin6_flowinfo = ip6_flowinfo(ip6);
 
 		sin6->sin6_scope_id = ipv6_iface_scope_id(&sin6->sin6_addr,
 							  IP6CB(skb)->iif);
+		*addr_len = sizeof(*sin6);
 
 		if (inet6_sk(sk)->rxopt.all)
 			pingv6_ops.ip6_datagram_recv_ctl(sk, msg, skb);
```
