# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1677_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1677_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 508-551 of the vulnerable file.

out:
	return err;

csum_copy_err:
	slow = lock_sock_fast(sk);
	if (!skb_kill_datagram(sk, skb, flags)) {
		if (is_udp4) {
			UDP_INC_STATS_USER(sock_net(sk),
					UDP_MIB_CSUMERRORS, is_udplite);
			UDP_INC_STATS_USER(sock_net(sk),
					UDP_MIB_INERRORS, is_udplite);
		} else {
			UDP6_INC_STATS_USER(sock_net(sk),
					UDP_MIB_CSUMERRORS, is_udplite);
			UDP6_INC_STATS_USER(sock_net(sk),
					UDP_MIB_INERRORS, is_udplite);
		}
	}
	unlock_sock_fast(sk, slow);

	if (noblock)
		return -EAGAIN;

	/* starting over for a new packet */
	msg->msg_flags &= ~MSG_TRUNC;
	goto try_again;
}

void __udp6_lib_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
		    u8 type, u8 code, int offset, __be32 info,
		    struct udp_table *udptable)
{
	struct ipv6_pinfo *np;
	const struct ipv6hdr *hdr = (const struct ipv6hdr *)skb->data;
	const struct in6_addr *saddr = &hdr->saddr;
	const struct in6_addr *daddr = &hdr->daddr;
	struct udphdr *uh = (struct udphdr *)(skb->data+offset);
	struct sock *sk;
	int err;
	struct net *net = dev_net(skb->dev);

	sk = __udp6_lib_lookup(net, daddr, uh->dest,
			       saddr, uh->source, inet6_iif(skb), udptable);
	if (!sk) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -525,10 +525,8 @@
 	}
 	unlock_sock_fast(sk, slow);
 
-	if (noblock)
-		return -EAGAIN;
-
-	/* starting over for a new packet */
+	/* starting over for a new packet, but check if we need to yield */
+	cond_resched();
 	msg->msg_flags &= ~MSG_TRUNC;
 	goto try_again;
 }
```
