# CrossVul Fix Pair: Improperly Implemented Security Check for Standard in c
**Pair ID:** 4847_1
**Vulnerability Class:** Improperly Implemented Security Check for Standard
**CWE:** CWE-358
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4847_1`)

## Vulnerability Information & PoC

## Description
Improperly Implemented Security Check for Standard - The product does not implement or incorrectly implements one or more security-relevant checks as specified by the design of a standardized algorithm, protocol, or technique.

## Vulnerable Code
```c
Lines 385-425 of the vulnerable file.

{
	return __udp6_lib_lookup(net, saddr, sport, daddr, dport, dif, &udp_table);
}
EXPORT_SYMBOL_GPL(udp6_lib_lookup);

/*
 *	This should be easy, if there is something there we
 *	return it, otherwise we block.
 */

int udpv6_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		  int noblock, int flags, int *addr_len)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int peeked, off = 0;
	int err;
	int is_udplite = IS_UDPLITE(sk);
	int is_udp4;
	bool slow;

	if (flags & MSG_ERRQUEUE)
		return ipv6_recv_error(sk, msg, len, addr_len);

	if (np->rxpmtu && np->rxopt.bits.rxpmtu)
		return ipv6_recv_rxpmtu(sk, msg, len, addr_len);

try_again:
	skb = __skb_recv_datagram(sk, flags | (noblock ? MSG_DONTWAIT : 0),
				  &peeked, &off, &err);
	if (!skb)
		goto out;

	ulen = skb->len - sizeof(struct udphdr);
	copied = len;
	if (copied > ulen)
		copied = ulen;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -402,6 +402,7 @@
 	int peeked, off = 0;
 	int err;
 	int is_udplite = IS_UDPLITE(sk);
+	bool checksum_valid = false;
 	int is_udp4;
 	bool slow;
 
@@ -433,11 +434,12 @@
 	 */
 
 	if (copied < ulen || UDP_SKB_CB(skb)->partial_cov) {
-		if (udp_lib_checksum_complete(skb))
+		checksum_valid = !udp_lib_checksum_complete(skb);
+		if (!checksum_valid)
 			goto csum_copy_err;
 	}
 
-	if (skb_csum_unnecessary(skb))
+	if (checksum_valid || skb_csum_unnecessary(skb))
 		err = skb_copy_datagram_msg(skb, sizeof(struct udphdr),
 					    msg, copied);
 	else {
```
