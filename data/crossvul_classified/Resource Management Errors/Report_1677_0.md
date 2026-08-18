# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1677_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1677_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1328-1371 of the vulnerable file.

	if (inet->cmsg_flags)
		ip_cmsg_recv_offset(msg, skb, sizeof(struct udphdr));

	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

out_free:
	skb_free_datagram_locked(sk, skb);
out:
	return err;

csum_copy_err:
	slow = lock_sock_fast(sk);
	if (!skb_kill_datagram(sk, skb, flags)) {
		UDP_INC_STATS_USER(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
		UDP_INC_STATS_USER(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	}
	unlock_sock_fast(sk, slow);

	if (noblock)
		return -EAGAIN;

	/* starting over for a new packet */
	msg->msg_flags &= ~MSG_TRUNC;
	goto try_again;
}

int udp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	/*
	 *	1003.1g - break association.
	 */

	sk->sk_state = TCP_CLOSE;
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sock_rps_reset_rxhash(sk);
	sk->sk_bound_dev_if = 0;
	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1345,10 +1345,8 @@
 	}
 	unlock_sock_fast(sk, slow);
 
-	if (noblock)
-		return -EAGAIN;
-
-	/* starting over for a new packet */
+	/* starting over for a new packet, but check if we need to yield */
+	cond_resched();
 	msg->msg_flags &= ~MSG_TRUNC;
 	goto try_again;
 }
```
