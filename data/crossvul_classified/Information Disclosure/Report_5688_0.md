# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5688_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5688_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1311-1351 of the vulnerable file.

		if (!skb)
			break;
		iucv_process_message(sk, skb, p->path, &p->msg);
		list_del(&p->list);
		kfree(p);
		if (!skb_queue_empty(&iucv->backlog_skb_q))
			break;
	}
}

static int iucv_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
			     struct msghdr *msg, size_t len, int flags)
{
	int noblock = flags & MSG_DONTWAIT;
	struct sock *sk = sock->sk;
	struct iucv_sock *iucv = iucv_sk(sk);
	unsigned int copied, rlen;
	struct sk_buff *skb, *rskb, *cskb;
	int err = 0;

	if ((sk->sk_state == IUCV_DISCONN) &&
	    skb_queue_empty(&iucv->backlog_skb_q) &&
	    skb_queue_empty(&sk->sk_receive_queue) &&
	    list_empty(&iucv->message_q.list))
		return 0;

	if (flags & (MSG_OOB))
		return -EOPNOTSUPP;

	/* receive/dequeue next skb:
	 * the function understands MSG_PEEK and, thus, does not dequeue skb */
	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb) {
		if (sk->sk_shutdown & RCV_SHUTDOWN)
			return 0;
		return err;
	}

	rlen   = skb->len;		/* real length of skb */
	copied = min_t(unsigned int, rlen, len);
	if (!rlen)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1327,6 +1327,8 @@
 	unsigned int copied, rlen;
 	struct sk_buff *skb, *rskb, *cskb;
 	int err = 0;
+
+	msg->msg_namelen = 0;
 
 	if ((sk->sk_state == IUCV_DISCONN) &&
 	    skb_queue_empty(&iucv->backlog_skb_q) &&
```
