# CrossVul Fix Pair: Improperly Implemented Security Check for Standard in c
**Pair ID:** 4847_0
**Vulnerability Class:** Improperly Implemented Security Check for Standard
**CWE:** CWE-358
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4847_0`)

## Vulnerability Information & PoC

## Description
Improperly Implemented Security Check for Standard - The product does not implement or incorrectly implements one or more security-relevant checks as specified by the design of a standardized algorithm, protocol, or technique.

## Vulnerable Code
```c
Lines 1254-1294 of the vulnerable file.


	return 0;
}
EXPORT_SYMBOL(udp_ioctl);

/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 */

int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
		int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int peeked, off = 0;
	int err;
	int is_udplite = IS_UDPLITE(sk);
	bool slow;

	if (flags & MSG_ERRQUEUE)
		return ip_recv_error(sk, msg, len, addr_len);

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

	/*
	 * If checksum is needed at all, try to do it while copying the
	 * data.  If the data is truncated, or if we only want a partial
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1271,6 +1271,7 @@
 	int peeked, off = 0;
 	int err;
 	int is_udplite = IS_UDPLITE(sk);
+	bool checksum_valid = false;
 	bool slow;
 
 	if (flags & MSG_ERRQUEUE)
@@ -1296,11 +1297,12 @@
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
