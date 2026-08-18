# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5845_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5845_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 962-1003 of the vulnerable file.

	.start_xmit = pppoe_xmit,
};

static int pppoe_recvmsg(struct kiocb *iocb, struct socket *sock,
		  struct msghdr *m, size_t total_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int error = 0;

	if (sk->sk_state & PPPOX_BOUND) {
		error = -EIO;
		goto end;
	}

	skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT,
				flags & MSG_DONTWAIT, &error);
	if (error < 0)
		goto end;

	m->msg_namelen = 0;

	if (skb) {
		total_len = min_t(size_t, total_len, skb->len);
		error = skb_copy_datagram_iovec(skb, 0, m->msg_iov, total_len);
		if (error == 0) {
			consume_skb(skb);
			return total_len;
		}
	}

	kfree_skb(skb);
end:
	return error;
}

#ifdef CONFIG_PROC_FS
static int pppoe_seq_show(struct seq_file *seq, void *v)
{
	struct pppox_sock *po;
	char *dev_name;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -979,8 +979,6 @@
 	if (error < 0)
 		goto end;
 
-	m->msg_namelen = 0;
-
 	if (skb) {
 		total_len = min_t(size_t, total_len, skb->len);
 		error = skb_copy_datagram_iovec(skb, 0, m->msg_iov, total_len);
```
