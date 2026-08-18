# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5845_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5845_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 100-140 of the vulnerable file.

	return 0;
}

static inline void
mISDN_sock_cmsg(struct sock *sk, struct msghdr *msg, struct sk_buff *skb)
{
	struct timeval	tv;

	if (_pms(sk)->cmask & MISDN_TIME_STAMP) {
		skb_get_timestamp(skb, &tv);
		put_cmsg(msg, SOL_MISDN, MISDN_TIME_STAMP, sizeof(tv), &tv);
	}
}

static int
mISDN_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
		   struct msghdr *msg, size_t len, int flags)
{
	struct sk_buff		*skb;
	struct sock		*sk = sock->sk;
	struct sockaddr_mISDN	*maddr;

	int		copied, err;

	if (*debug & DEBUG_SOCKET)
		printk(KERN_DEBUG "%s: len %d, flags %x ch.nr %d, proto %x\n",
		       __func__, (int)len, flags, _pms(sk)->ch.nr,
		       sk->sk_protocol);
	if (flags & (MSG_OOB))
		return -EOPNOTSUPP;

	if (sk->sk_state == MISDN_CLOSED)
		return 0;

	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	if (msg->msg_namelen >= sizeof(struct sockaddr_mISDN)) {
		msg->msg_namelen = sizeof(struct sockaddr_mISDN);
		maddr = (struct sockaddr_mISDN *)msg->msg_name;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,7 +117,6 @@
 {
 	struct sk_buff		*skb;
 	struct sock		*sk = sock->sk;
-	struct sockaddr_mISDN	*maddr;
 
 	int		copied, err;
 
@@ -135,9 +134,9 @@
 	if (!skb)
 		return err;
 
-	if (msg->msg_namelen >= sizeof(struct sockaddr_mISDN)) {
-		msg->msg_namelen = sizeof(struct sockaddr_mISDN);
-		maddr = (struct sockaddr_mISDN *)msg->msg_name;
+	if (msg->msg_name) {
+		struct sockaddr_mISDN *maddr = msg->msg_name;
+
 		maddr->family = AF_ISDN;
 		maddr->dev = _pms(sk)->dev->id;
 		if ((sk->sk_protocol == ISDN_P_LAPD_TE) ||
@@ -150,11 +149,7 @@
 			maddr->sapi = _pms(sk)->ch.addr & 0xFF;
 			maddr->tei =  (_pms(sk)->ch.addr >> 8) & 0xFF;
 		}
-	} else {
-		if (msg->msg_namelen)
-			printk(KERN_WARNING "%s: too small namelen %d\n",
-			       __func__, msg->msg_namelen);
-		msg->msg_namelen = 0;
+		msg->msg_namelen = sizeof(*maddr);
 	}
 
 	copied = skb->len + MISDN_HEADER_LEN;
```
