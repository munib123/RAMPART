# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5689_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5689_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 673-713 of the vulnerable file.


	copied = skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (err)
		goto done;

	sock_recv_timestamp(msg, sk, skb);

	/* Copy the address. */
	if (lsa) {
		lsa->l2tp_family = AF_INET6;
		lsa->l2tp_unused = 0;
		lsa->l2tp_addr = ipv6_hdr(skb)->saddr;
		lsa->l2tp_flowinfo = 0;
		lsa->l2tp_scope_id = 0;
		if (ipv6_addr_type(&lsa->l2tp_addr) & IPV6_ADDR_LINKLOCAL)
			lsa->l2tp_scope_id = IP6CB(skb)->iif;
	}

	if (np->rxopt.all)
		ip6_datagram_recv_ctl(sk, msg, skb);

	if (flags & MSG_TRUNC)
		copied = skb->len;
done:
	skb_free_datagram(sk, skb);
out:
	return err ? err : copied;
}

static struct proto l2tp_ip6_prot = {
	.name		   = "L2TP/IPv6",
	.owner		   = THIS_MODULE,
	.init		   = l2tp_ip6_open,
	.close		   = l2tp_ip6_close,
	.bind		   = l2tp_ip6_bind,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -690,6 +690,7 @@
 		lsa->l2tp_addr = ipv6_hdr(skb)->saddr;
 		lsa->l2tp_flowinfo = 0;
 		lsa->l2tp_scope_id = 0;
+		lsa->l2tp_conn_id = 0;
 		if (ipv6_addr_type(&lsa->l2tp_addr) & IPV6_ADDR_LINKLOCAL)
 			lsa->l2tp_scope_id = IP6CB(skb)->iif;
 	}
```
