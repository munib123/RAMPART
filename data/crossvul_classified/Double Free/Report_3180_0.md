# CrossVul Fix Pair: Double Free in c
**Pair ID:** 3180_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3180_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 4845-4885 of the vulnerable file.

		return -EINVAL;
	len = sizeof(int);
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &sctp_sk(sk)->autoclose, sizeof(int)))
		return -EFAULT;
	return 0;
}

/* Helper routine to branch off an association to a new socket.  */
int sctp_do_peeloff(struct sock *sk, sctp_assoc_t id, struct socket **sockp)
{
	struct sctp_association *asoc = sctp_id2assoc(sk, id);
	struct sctp_sock *sp = sctp_sk(sk);
	struct socket *sock;
	int err = 0;

	if (!asoc)
		return -EINVAL;

	/* An association cannot be branched off from an already peeled-off
	 * socket, nor is this supported for tcp style sockets.
	 */
	if (!sctp_style(sk, UDP))
		return -EINVAL;

	/* Create a new socket.  */
	err = sock_create(sk->sk_family, SOCK_SEQPACKET, IPPROTO_SCTP, &sock);
	if (err < 0)
		return err;

	sctp_copy_sock(sock->sk, sk, asoc);

	/* Make peeled-off sockets more like 1-1 accepted sockets.
	 * Set the daddr and initialize id to something more random
	 */
	sp->pf->to_sk_daddr(&asoc->peer.primary_addr, sk);

	/* Populate the fields of the newsk from the oldsk and migrate the
	 * asoc to the newsk.
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4862,6 +4862,12 @@
 	if (!asoc)
 		return -EINVAL;
 
+	/* If there is a thread waiting on more sndbuf space for
+	 * sending on this asoc, it cannot be peeled.
+	 */
+	if (waitqueue_active(&asoc->wait))
+		return -EBUSY;
+
 	/* An association cannot be branched off from an already peeled-off
 	 * socket, nor is this supported for tcp style sockets.
 	 */
@@ -7599,8 +7605,6 @@
 		 */
 		release_sock(sk);
 		current_timeo = schedule_timeout(current_timeo);
-		if (sk != asoc->base.sk)
-			goto do_error;
 		lock_sock(sk);
 
 		*timeo_p = current_timeo;
```
