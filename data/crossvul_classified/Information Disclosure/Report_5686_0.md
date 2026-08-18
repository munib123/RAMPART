# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5686_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5686_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 268-308 of the vulnerable file.

			caif_flow_ctrl(sk, CAIF_MODEMCMD_FLOW_ON_REQ);
	}
}

/*
 * Copied from unix_dgram_recvmsg, but removed credit checks,
 * changed locking, address handling and added MSG_TRUNC.
 */
static int caif_seqpkt_recvmsg(struct kiocb *iocb, struct socket *sock,
				struct msghdr *m, size_t len, int flags)

{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int ret;
	int copylen;

	ret = -EOPNOTSUPP;
	if (m->msg_flags&MSG_OOB)
		goto read_error;

	skb = skb_recv_datagram(sk, flags, 0 , &ret);
	if (!skb)
		goto read_error;
	copylen = skb->len;
	if (len < copylen) {
		m->msg_flags |= MSG_TRUNC;
		copylen = len;
	}

	ret = skb_copy_datagram_iovec(skb, 0, m->msg_iov, copylen);
	if (ret)
		goto out_free;

	ret = (flags & MSG_TRUNC) ? skb->len : copylen;
out_free:
	skb_free_datagram(sk, skb);
	caif_check_flow_release(sk);
	return ret;

read_error:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -285,6 +285,8 @@
 	ret = -EOPNOTSUPP;
 	if (m->msg_flags&MSG_OOB)
 		goto read_error;
+
+	m->msg_namelen = 0;
 
 	skb = skb_recv_datagram(sk, flags, 0 , &ret);
 	if (!skb)
```
