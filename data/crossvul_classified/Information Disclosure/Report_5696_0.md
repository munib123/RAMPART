# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5696_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5696_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1719-1759 of the vulnerable file.


	return err - sizeof(*dg);
}

static int vmci_transport_dgram_dequeue(struct kiocb *kiocb,
					struct vsock_sock *vsk,
					struct msghdr *msg, size_t len,
					int flags)
{
	int err;
	int noblock;
	struct vmci_datagram *dg;
	size_t payload_len;
	struct sk_buff *skb;

	noblock = flags & MSG_DONTWAIT;

	if (flags & MSG_OOB || flags & MSG_ERRQUEUE)
		return -EOPNOTSUPP;

	/* Retrieve the head sk_buff from the socket's receive queue. */
	err = 0;
	skb = skb_recv_datagram(&vsk->sk, flags, noblock, &err);
	if (err)
		return err;

	if (!skb)
		return -EAGAIN;

	dg = (struct vmci_datagram *)skb->data;
	if (!dg)
		/* err is 0, meaning we read zero bytes. */
		goto out;

	payload_len = dg->payload_size;
	/* Ensure the sk_buff matches the payload size claimed in the packet. */
	if (payload_len != skb->len - sizeof(*dg)) {
		err = -EINVAL;
		goto out;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1736,6 +1736,8 @@
 	if (flags & MSG_OOB || flags & MSG_ERRQUEUE)
 		return -EOPNOTSUPP;
 
+	msg->msg_namelen = 0;
+
 	/* Retrieve the head sk_buff from the socket's receive queue. */
 	err = 0;
 	skb = skb_recv_datagram(&vsk->sk, flags, noblock, &err);
@@ -1768,7 +1770,6 @@
 	if (err)
 		goto out;
 
-	msg->msg_namelen = 0;
 	if (msg->msg_name) {
 		struct sockaddr_vm *vm_addr;
 
```
