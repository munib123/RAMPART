# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3255_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3255_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 635-675 of the vulnerable file.

	return ret;
}

int sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
	int err = security_socket_sendmsg(sock, msg,
					  msg_data_left(msg));

	return err ?: sock_sendmsg_nosec(sock, msg);
}
EXPORT_SYMBOL(sock_sendmsg);

int kernel_sendmsg(struct socket *sock, struct msghdr *msg,
		   struct kvec *vec, size_t num, size_t size)
{
	iov_iter_kvec(&msg->msg_iter, WRITE | ITER_KVEC, vec, num, size);
	return sock_sendmsg(sock, msg);
}
EXPORT_SYMBOL(kernel_sendmsg);

/*
 * called from sock_recv_timestamp() if sock_flag(sk, SOCK_RCVTSTAMP)
 */
void __sock_recv_timestamp(struct msghdr *msg, struct sock *sk,
	struct sk_buff *skb)
{
	int need_software_tstamp = sock_flag(sk, SOCK_RCVTSTAMP);
	struct scm_timestamping tss;
	int empty = 1;
	struct skb_shared_hwtstamps *shhwtstamps =
		skb_hwtstamps(skb);

	/* Race occurred between timestamp enabling and packet
	   receiving.  Fill in the current time for now. */
	if (need_software_tstamp && skb->tstamp == 0)
		__net_timestamp(skb);

	if (need_software_tstamp) {
		if (!sock_flag(sk, SOCK_RCVTSTAMPNS)) {
			struct timeval tv;
			skb_get_timestamp(skb, &tv);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -652,6 +652,16 @@
 }
 EXPORT_SYMBOL(kernel_sendmsg);
 
+static bool skb_is_err_queue(const struct sk_buff *skb)
+{
+	/* pkt_type of skbs enqueued on the error queue are set to
+	 * PACKET_OUTGOING in skb_set_err_queue(). This is only safe to do
+	 * in recvmsg, since skbs received on a local socket will never
+	 * have a pkt_type of PACKET_OUTGOING.
+	 */
+	return skb->pkt_type == PACKET_OUTGOING;
+}
+
 /*
  * called from sock_recv_timestamp() if sock_flag(sk, SOCK_RCVTSTAMP)
  */
@@ -695,7 +705,8 @@
 		put_cmsg(msg, SOL_SOCKET,
 			 SCM_TIMESTAMPING, sizeof(tss), &tss);
 
-		if (skb->len && (sk->sk_tsflags & SOF_TIMESTAMPING_OPT_STATS))
+		if (skb_is_err_queue(skb) && skb->len &&
+		    (sk->sk_tsflags & SOF_TIMESTAMPING_OPT_STATS))
 			put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMPING_OPT_STATS,
 				 skb->len, skb->data);
 	}
```
