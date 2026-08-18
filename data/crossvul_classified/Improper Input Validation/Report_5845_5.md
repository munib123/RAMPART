# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5845_5
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5845_5`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1718-1758 of the vulnerable file.

		    gsat.sat_addr = rt->gateway;
		    usat = &gsat;
		}

		/*
		 * If it fails it is queued/sent above in the aarp queue
		 */
		aarp_send_ddp(dev, skb, &usat->sat_addr, NULL);
	}
	SOCK_DEBUG(sk, "SK %p: Done write (%Zd).\n", sk, len);

out:
	release_sock(sk);
	return err ? : len;
}

static int atalk_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
			 size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_at *sat = (struct sockaddr_at *)msg->msg_name;
	struct ddpehdr *ddp;
	int copied = 0;
	int offset = 0;
	int err = 0;
	struct sk_buff *skb;

	skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT,
						flags & MSG_DONTWAIT, &err);
	lock_sock(sk);

	if (!skb)
		goto out;

	/* FIXME: use skb->cb to be able to use shared skbs */
	ddp = ddp_hdr(skb);
	copied = ntohs(ddp->deh_len_hops) & 1023;

	if (sk->sk_type != SOCK_RAW) {
		offset = sizeof(*ddp);
		copied -= offset;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1735,7 +1735,6 @@
 			 size_t size, int flags)
 {
 	struct sock *sk = sock->sk;
-	struct sockaddr_at *sat = (struct sockaddr_at *)msg->msg_name;
 	struct ddpehdr *ddp;
 	int copied = 0;
 	int offset = 0;
@@ -1764,14 +1763,13 @@
 	}
 	err = skb_copy_datagram_iovec(skb, offset, msg->msg_iov, copied);
 
-	if (!err) {
-		if (sat) {
-			sat->sat_family      = AF_APPLETALK;
-			sat->sat_port        = ddp->deh_sport;
-			sat->sat_addr.s_node = ddp->deh_snode;
-			sat->sat_addr.s_net  = ddp->deh_snet;
-		}
-		msg->msg_namelen = sizeof(*sat);
+	if (!err && msg->msg_name) {
+		struct sockaddr_at *sat = msg->msg_name;
+		sat->sat_family      = AF_APPLETALK;
+		sat->sat_port        = ddp->deh_sport;
+		sat->sat_addr.s_node = ddp->deh_snode;
+		sat->sat_addr.s_net  = ddp->deh_snet;
+		msg->msg_namelen     = sizeof(*sat);
 	}
 
 	skb_free_datagram(sk, skb);	/* Free the datagram. */
```
