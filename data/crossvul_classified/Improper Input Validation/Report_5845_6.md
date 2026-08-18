# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5845_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5845_6`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 514-555 of the vulnerable file.

	error = __vcc_connect(vcc, dev, vpi, vci);
	if (error) {
		atm_dev_put(dev);
		return error;
	}
	if (vpi == ATM_VPI_UNSPEC || vci == ATM_VCI_UNSPEC)
		set_bit(ATM_VF_PARTIAL, &vcc->flags);
	if (test_bit(ATM_VF_READY, &ATM_SD(sock)->flags))
		sock->state = SS_CONNECTED;
	return 0;
}

int vcc_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct atm_vcc *vcc;
	struct sk_buff *skb;
	int copied, error = -EINVAL;

	msg->msg_namelen = 0;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;

	/* only handle MSG_DONTWAIT and MSG_PEEK */
	if (flags & ~(MSG_DONTWAIT | MSG_PEEK))
		return -EOPNOTSUPP;

	vcc = ATM_SD(sock);
	if (test_bit(ATM_VF_RELEASED, &vcc->flags) ||
	    test_bit(ATM_VF_CLOSE, &vcc->flags) ||
	    !test_bit(ATM_VF_READY, &vcc->flags))
		return 0;

	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &error);
	if (!skb)
		return error;

	copied = skb->len;
	if (copied > size) {
		copied = size;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -531,8 +531,6 @@
 	struct sk_buff *skb;
 	int copied, error = -EINVAL;
 
-	msg->msg_namelen = 0;
-
 	if (sock->state != SS_CONNECTED)
 		return -ENOTCONN;
 
```
