# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2838_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2838_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 4889-4929 of the vulnerable file.

	if (sctp_style(sk, TCP))
		return -EOPNOTSUPP;
	if (len < sizeof(int))
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

	/* If there is a thread waiting on more sndbuf space for
	 * sending on this asoc, it cannot be peeled.
	 */
	if (waitqueue_active(&asoc->wait))
		return -EBUSY;

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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4905,6 +4905,10 @@
 	struct sctp_sock *sp = sctp_sk(sk);
 	struct socket *sock;
 	int err = 0;
+
+	/* Do not peel off from one netns to another one. */
+	if (!net_eq(current->nsproxy->net_ns, sock_net(sk)))
+		return -EINVAL;
 
 	if (!asoc)
 		return -EINVAL;
```
