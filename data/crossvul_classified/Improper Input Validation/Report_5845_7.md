# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5845_7
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5845_7`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1619-1660 of the vulnerable file.


	/* Now we can treat all alike */
	skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT,
				flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		goto out;

	if (!ax25_sk(sk)->pidincl)
		skb_pull(skb, 1);		/* Remove PID */

	skb_reset_transport_header(skb);
	copied = skb->len;

	if (copied > size) {
		copied = size;
		msg->msg_flags |= MSG_TRUNC;
	}

	skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);

	if (msg->msg_namelen != 0) {
		struct sockaddr_ax25 *sax = (struct sockaddr_ax25 *)msg->msg_name;
		ax25_digi digi;
		ax25_address src;
		const unsigned char *mac = skb_mac_header(skb);

		memset(sax, 0, sizeof(struct full_sockaddr_ax25));
		ax25_addr_parse(mac + 1, skb->data - mac - 1, &src, NULL,
				&digi, NULL, NULL);
		sax->sax25_family = AF_AX25;
		/* We set this correctly, even though we may not let the
		   application know the digi calls further down (because it
		   did NOT ask to know them).  This could get political... **/
		sax->sax25_ndigis = digi.ndigi;
		sax->sax25_call   = src;

		if (sax->sax25_ndigis != 0) {
			int ct;
			struct full_sockaddr_ax25 *fsa = (struct full_sockaddr_ax25 *)sax;

			for (ct = 0; ct < digi.ndigi; ct++)
				fsa->fsa_digipeater[ct] = digi.calls[ct];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1636,11 +1636,11 @@
 
 	skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
 
-	if (msg->msg_namelen != 0) {
-		struct sockaddr_ax25 *sax = (struct sockaddr_ax25 *)msg->msg_name;
+	if (msg->msg_name) {
 		ax25_digi digi;
 		ax25_address src;
 		const unsigned char *mac = skb_mac_header(skb);
+		struct sockaddr_ax25 *sax = msg->msg_name;
 
 		memset(sax, 0, sizeof(struct full_sockaddr_ax25));
 		ax25_addr_parse(mac + 1, skb->data - mac - 1, &src, NULL,
```
