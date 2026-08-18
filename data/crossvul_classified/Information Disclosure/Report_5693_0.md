# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5693_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5693_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 629-669 of the vulnerable file.

		release_sock(sk);
		return -ENOTCONN;
	}

	release_sock(sk);

	return nfc_llcp_send_i_frame(llcp_sock, msg, len);
}

static int llcp_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
			     struct msghdr *msg, size_t len, int flags)
{
	int noblock = flags & MSG_DONTWAIT;
	struct sock *sk = sock->sk;
	unsigned int copied, rlen;
	struct sk_buff *skb, *cskb;
	int err = 0;

	pr_debug("%p %zu\n", sk, len);

	lock_sock(sk);

	if (sk->sk_state == LLCP_CLOSED &&
	    skb_queue_empty(&sk->sk_receive_queue)) {
		release_sock(sk);
		return 0;
	}

	release_sock(sk);

	if (flags & (MSG_OOB))
		return -EOPNOTSUPP;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb) {
		pr_err("Recv datagram failed state %d %d %d",
		       sk->sk_state, err, sock_error(sk));

		if (sk->sk_shutdown & RCV_SHUTDOWN)
			return 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -646,6 +646,8 @@
 
 	pr_debug("%p %zu\n", sk, len);
 
+	msg->msg_namelen = 0;
+
 	lock_sock(sk);
 
 	if (sk->sk_state == LLCP_CLOSED &&
@@ -691,6 +693,7 @@
 
 		pr_debug("Datagram socket %d %d\n", ui_cb->dsap, ui_cb->ssap);
 
+		memset(sockaddr, 0, sizeof(*sockaddr));
 		sockaddr->sa_family = AF_NFC;
 		sockaddr->nfc_protocol = NFC_PROTO_NFC_DEP;
 		sockaddr->dsap = ui_cb->dsap;
```
