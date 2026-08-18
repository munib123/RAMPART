# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1847_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1847_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 317-357 of the vulnerable file.


	BT_DBG("sock %p", sock);

	sock->state = SS_UNCONNECTED;

	if (sock->type != SOCK_STREAM && sock->type != SOCK_RAW)
		return -ESOCKTNOSUPPORT;

	sock->ops = &rfcomm_sock_ops;

	sk = rfcomm_sock_alloc(net, sock, protocol, GFP_ATOMIC, kern);
	if (!sk)
		return -ENOMEM;

	rfcomm_sock_init(sk, NULL);
	return 0;
}

static int rfcomm_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_rc *sa = (struct sockaddr_rc *) addr;
	struct sock *sk = sock->sk;
	int chan = sa->rc_channel;
	int err = 0;

	BT_DBG("sk %p %pMR", sk, &sa->rc_bdaddr);

	if (!addr || addr->sa_family != AF_BLUETOOTH)
		return -EINVAL;

	lock_sock(sk);

	if (sk->sk_state != BT_OPEN) {
		err = -EBADFD;
		goto done;
	}

	if (sk->sk_type != SOCK_STREAM) {
		err = -EINVAL;
		goto done;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -334,15 +334,18 @@
 
 static int rfcomm_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
 {
-	struct sockaddr_rc *sa = (struct sockaddr_rc *) addr;
+	struct sockaddr_rc sa;
 	struct sock *sk = sock->sk;
-	int chan = sa->rc_channel;
-	int err = 0;
-
-	BT_DBG("sk %p %pMR", sk, &sa->rc_bdaddr);
+	int len, err = 0;
 
 	if (!addr || addr->sa_family != AF_BLUETOOTH)
 		return -EINVAL;
+
+	memset(&sa, 0, sizeof(sa));
+	len = min_t(unsigned int, sizeof(sa), addr_len);
+	memcpy(&sa, addr, len);
+
+	BT_DBG("sk %p %pMR", sk, &sa.rc_bdaddr);
 
 	lock_sock(sk);
 
@@ -358,12 +361,13 @@
 
 	write_lock(&rfcomm_sk_list.lock);
 
-	if (chan && __rfcomm_get_listen_sock_by_addr(chan, &sa->rc_bdaddr)) {
+	if (sa.rc_channel &&
+	    __rfcomm_get_listen_sock_by_addr(sa.rc_channel, &sa.rc_bdaddr)) {
 		err = -EADDRINUSE;
 	} else {
 		/* Save source address */
-		bacpy(&rfcomm_pi(sk)->src, &sa->rc_bdaddr);
-		rfcomm_pi(sk)->channel = chan;
+		bacpy(&rfcomm_pi(sk)->src, &sa.rc_bdaddr);
+		rfcomm_pi(sk)->channel = sa.rc_channel;
 		sk->sk_state = BT_BOUND;
 	}
 
```
