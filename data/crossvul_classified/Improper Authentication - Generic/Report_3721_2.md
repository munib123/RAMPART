# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 3721_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3721_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 1433-1473 of the vulnerable file.

			      struct msghdr *msg, size_t len)
{
	struct sock_iocb *siocb = kiocb_to_siocb(kiocb);
	struct sock *sk = sock->sk;
	struct net *net = sock_net(sk);
	struct unix_sock *u = unix_sk(sk);
	struct sockaddr_un *sunaddr = msg->msg_name;
	struct sock *other = NULL;
	int namelen = 0; /* fake GCC */
	int err;
	unsigned int hash;
	struct sk_buff *skb;
	long timeo;
	struct scm_cookie tmp_scm;
	int max_level;
	int data_len = 0;

	if (NULL == siocb->scm)
		siocb->scm = &tmp_scm;
	wait_for_unix_gc();
	err = scm_send(sock, msg, siocb->scm);
	if (err < 0)
		return err;

	err = -EOPNOTSUPP;
	if (msg->msg_flags&MSG_OOB)
		goto out;

	if (msg->msg_namelen) {
		err = unix_mkname(sunaddr, msg->msg_namelen, &hash);
		if (err < 0)
			goto out;
		namelen = err;
	} else {
		sunaddr = NULL;
		err = -ENOTCONN;
		other = unix_peer_get(sk);
		if (!other)
			goto out;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1450,7 +1450,7 @@
 	if (NULL == siocb->scm)
 		siocb->scm = &tmp_scm;
 	wait_for_unix_gc();
-	err = scm_send(sock, msg, siocb->scm);
+	err = scm_send(sock, msg, siocb->scm, false);
 	if (err < 0)
 		return err;
 
@@ -1619,7 +1619,7 @@
 	if (NULL == siocb->scm)
 		siocb->scm = &tmp_scm;
 	wait_for_unix_gc();
-	err = scm_send(sock, msg, siocb->scm);
+	err = scm_send(sock, msg, siocb->scm, false);
 	if (err < 0)
 		return err;
 
```
