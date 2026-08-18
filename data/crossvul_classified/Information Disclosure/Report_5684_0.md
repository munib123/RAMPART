# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5684_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5684_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 591-631 of the vulnerable file.

		}

		sent += size;
		len  -= size;
	}

	release_sock(sk);

	return sent;
}

static int rfcomm_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct rfcomm_dlc *d = rfcomm_pi(sk)->dlc;
	int len;

	if (test_and_clear_bit(RFCOMM_DEFER_SETUP, &d->flags)) {
		rfcomm_dlc_accept(d);
		return 0;
	}

	len = bt_sock_stream_recvmsg(iocb, sock, msg, size, flags);

	lock_sock(sk);
	if (!(flags & MSG_PEEK) && len > 0)
		atomic_sub(len, &sk->sk_rmem_alloc);

	if (atomic_read(&sk->sk_rmem_alloc) <= (sk->sk_rcvbuf >> 2))
		rfcomm_dlc_unthrottle(rfcomm_pi(sk)->dlc);
	release_sock(sk);

	return len;
}

static int rfcomm_sock_setsockopt_old(struct socket *sock, int optname, char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	int err = 0;
	u32 opt;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -608,6 +608,7 @@
 
 	if (test_and_clear_bit(RFCOMM_DEFER_SETUP, &d->flags)) {
 		rfcomm_dlc_accept(d);
+		msg->msg_namelen = 0;
 		return 0;
 	}
 
```
