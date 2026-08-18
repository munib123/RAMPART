# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3696_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3696_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 393-433 of the vulnerable file.

	}

	return 0;
}

int rds_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		size_t size, int msg_flags)
{
	struct sock *sk = sock->sk;
	struct rds_sock *rs = rds_sk_to_rs(sk);
	long timeo;
	int ret = 0, nonblock = msg_flags & MSG_DONTWAIT;
	struct sockaddr_in *sin;
	struct rds_incoming *inc = NULL;

	/* udp_recvmsg()->sock_recvtimeo() gets away without locking too.. */
	timeo = sock_rcvtimeo(sk, nonblock);

	rdsdebug("size %zu flags 0x%x timeo %ld\n", size, msg_flags, timeo);

	if (msg_flags & MSG_OOB)
		goto out;

	while (1) {
		/* If there are pending notifications, do those - and nothing else */
		if (!list_empty(&rs->rs_notify_queue)) {
			ret = rds_notify_queue_get(rs, msg);
			break;
		}

		if (rs->rs_cong_notify) {
			ret = rds_notify_cong(rs, msg);
			break;
		}

		if (!rds_next_incoming(rs, &inc)) {
			if (nonblock) {
				ret = -EAGAIN;
				break;
			}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -410,6 +410,8 @@
 
 	rdsdebug("size %zu flags 0x%x timeo %ld\n", size, msg_flags, timeo);
 
+	msg->msg_namelen = 0;
+
 	if (msg_flags & MSG_OOB)
 		goto out;
 
@@ -485,6 +487,7 @@
 			sin->sin_port = inc->i_hdr.h_sport;
 			sin->sin_addr.s_addr = inc->i_saddr;
 			memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
+			msg->msg_namelen = sizeof(*sin);
 		}
 		break;
 	}
```
