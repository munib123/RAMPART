# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5844_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5844_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 448-490 of the vulnerable file.



/*
 *	This should be easy, if there is something there
 *	we return it, otherwise we block.
 */

static int rawv6_recvmsg(struct kiocb *iocb, struct sock *sk,
		  struct msghdr *msg, size_t len,
		  int noblock, int flags, int *addr_len)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)msg->msg_name;
	struct sk_buff *skb;
	size_t copied;
	int err;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	if (addr_len)
		*addr_len=sizeof(*sin6);

	if (flags & MSG_ERRQUEUE)
		return ipv6_recv_error(sk, msg, len);

	if (np->rxpmtu && np->rxopt.bits.rxpmtu)
		return ipv6_recv_rxpmtu(sk, msg, len);

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

	copied = skb->len;
	if (copied > len) {
		copied = len;
		msg->msg_flags |= MSG_TRUNC;
	}

	if (skb_csum_unnecessary(skb)) {
		err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	} else if (msg->msg_flags&MSG_TRUNC) {
		if (__skb_checksum_complete(skb))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -465,9 +465,6 @@
 	if (flags & MSG_OOB)
 		return -EOPNOTSUPP;
 
-	if (addr_len)
-		*addr_len=sizeof(*sin6);
-
 	if (flags & MSG_ERRQUEUE)
 		return ipv6_recv_error(sk, msg, len);
 
@@ -506,6 +503,7 @@
 		sin6->sin6_flowinfo = 0;
 		sin6->sin6_scope_id = ipv6_iface_scope_id(&sin6->sin6_addr,
 							  IP6CB(skb)->iif);
+		*addr_len = sizeof(*sin6);
 	}
 
 	sock_recv_ts_and_drops(msg, sk, skb);
```
