# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5690_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5690_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 703-743 of the vulnerable file.

 *
 *	Copy received data to the socket user.
 *	Returns non-negative upon success, negative otherwise.
 */
static int llc_ui_recvmsg(struct kiocb *iocb, struct socket *sock,
			  struct msghdr *msg, size_t len, int flags)
{
	struct sockaddr_llc *uaddr = (struct sockaddr_llc *)msg->msg_name;
	const int nonblock = flags & MSG_DONTWAIT;
	struct sk_buff *skb = NULL;
	struct sock *sk = sock->sk;
	struct llc_sock *llc = llc_sk(sk);
	unsigned long cpu_flags;
	size_t copied = 0;
	u32 peek_seq = 0;
	u32 *seq;
	unsigned long used;
	int target;	/* Read at least this many bytes */
	long timeo;

	lock_sock(sk);
	copied = -ENOTCONN;
	if (unlikely(sk->sk_type == SOCK_STREAM && sk->sk_state == TCP_LISTEN))
		goto out;

	timeo = sock_rcvtimeo(sk, nonblock);

	seq = &llc->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = llc->copied_seq;
		seq = &peek_seq;
	}

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	copied = 0;

	do {
		u32 offset;

		/*
		 * We need to check signals first, to get correct SIGURG
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -720,6 +720,8 @@
 	int target;	/* Read at least this many bytes */
 	long timeo;
 
+	msg->msg_namelen = 0;
+
 	lock_sock(sk);
 	copied = -ENOTCONN;
 	if (unlikely(sk->sk_type == SOCK_STREAM && sk->sk_state == TCP_LISTEN))
```
