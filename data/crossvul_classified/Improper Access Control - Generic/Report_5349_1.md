# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5349_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5349_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 1547-1587 of the vulnerable file.

	limit += 64*1024;

	/* In case all data was pulled from skb frags (in __pskb_pull_tail()),
	 * we can fix skb->truesize to its real value to avoid future drops.
	 * This is valid because skb is not yet charged to the socket.
	 * It has been noticed pure SACK packets were sometimes dropped
	 * (if cooked by drivers without copybreak feature).
	 */
	if (!skb->data_len)
		skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));

	if (unlikely(sk_add_backlog(sk, skb, limit))) {
		bh_unlock_sock(sk);
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPBACKLOGDROP);
		return true;
	}
	return false;
}
EXPORT_SYMBOL(tcp_add_backlog);

/*
 *	From tcp_input.c
 */

int tcp_v4_rcv(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	const struct iphdr *iph;
	const struct tcphdr *th;
	bool refcounted;
	struct sock *sk;
	int ret;

	if (skb->pkt_type != PACKET_HOST)
		goto discard_it;

	/* Count it even if it's bad */
	__TCP_INC_STATS(net, TCP_MIB_INSEGS);

	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
		goto discard_it;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1563,6 +1563,21 @@
 	return false;
 }
 EXPORT_SYMBOL(tcp_add_backlog);
+
+int tcp_filter(struct sock *sk, struct sk_buff *skb)
+{
+	struct tcphdr *th = (struct tcphdr *)skb->data;
+	unsigned int eaten = skb->len;
+	int err;
+
+	err = sk_filter_trim_cap(sk, skb, th->doff * 4);
+	if (!err) {
+		eaten -= skb->len;
+		TCP_SKB_CB(skb)->end_seq -= eaten;
+	}
+	return err;
+}
+EXPORT_SYMBOL(tcp_filter);
 
 /*
  *	From tcp_input.c
@@ -1676,8 +1691,10 @@
 
 	nf_reset(skb);
 
-	if (sk_filter(sk, skb))
+	if (tcp_filter(sk, skb))
 		goto discard_and_relse;
+	th = (const struct tcphdr *)skb->data;
+	iph = ip_hdr(skb);
 
 	skb->dev = NULL;
 
```
