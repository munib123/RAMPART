# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5845_8
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5845_8`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 207-248 of the vulnerable file.

	return NULL;
}
EXPORT_SYMBOL(bt_accept_dequeue);

int bt_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
				struct msghdr *msg, size_t len, int flags)
{
	int noblock = flags & MSG_DONTWAIT;
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	size_t copied;
	int err;

	BT_DBG("sock %p sk %p len %zu", sock, sk, len);

	if (flags & (MSG_OOB))
		return -EOPNOTSUPP;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb) {
		if (sk->sk_shutdown & RCV_SHUTDOWN) {
			msg->msg_namelen = 0;
			return 0;
		}
		return err;
	}

	copied = skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	skb_reset_transport_header(skb);
	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (err == 0) {
		sock_recv_ts_and_drops(msg, sk, skb);

		if (bt_sk(sk)->skb_msg_name)
			bt_sk(sk)->skb_msg_name(skb, msg->msg_name,
						&msg->msg_namelen);
		else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,10 +224,9 @@
 
 	skb = skb_recv_datagram(sk, flags, noblock, &err);
 	if (!skb) {
-		if (sk->sk_shutdown & RCV_SHUTDOWN) {
-			msg->msg_namelen = 0;
+		if (sk->sk_shutdown & RCV_SHUTDOWN)
 			return 0;
-		}
+
 		return err;
 	}
 
@@ -245,8 +244,6 @@
 		if (bt_sk(sk)->skb_msg_name)
 			bt_sk(sk)->skb_msg_name(skb, msg->msg_name,
 						&msg->msg_namelen);
-		else
-			msg->msg_namelen = 0;
 	}
 
 	skb_free_datagram(sk, skb);
@@ -294,8 +291,6 @@
 
 	if (flags & MSG_OOB)
 		return -EOPNOTSUPP;
-
-	msg->msg_namelen = 0;
 
 	BT_DBG("sk %p size %zu", sk, size);
 
```
