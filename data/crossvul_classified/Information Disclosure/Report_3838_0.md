# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3838_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3838_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 78-118 of the vulnerable file.

{
	struct sock *sk = sock->sk;
	int error;

	lock_sock(sk);
	error = vcc_getsockopt(sock, level, optname, optval, optlen);
	release_sock(sk);
	return error;
}

static int pvc_getname(struct socket *sock, struct sockaddr *sockaddr,
		       int *sockaddr_len, int peer)
{
	struct sockaddr_atmpvc *addr;
	struct atm_vcc *vcc = ATM_SD(sock);

	if (!vcc->dev || !test_bit(ATM_VF_ADDR, &vcc->flags))
		return -ENOTCONN;
	*sockaddr_len = sizeof(struct sockaddr_atmpvc);
	addr = (struct sockaddr_atmpvc *)sockaddr;
	addr->sap_family = AF_ATMPVC;
	addr->sap_addr.itf = vcc->dev->number;
	addr->sap_addr.vpi = vcc->vpi;
	addr->sap_addr.vci = vcc->vci;
	return 0;
}

static const struct proto_ops pvc_proto_ops = {
	.family =	PF_ATMPVC,
	.owner =	THIS_MODULE,

	.release =	vcc_release,
	.bind =		pvc_bind,
	.connect =	pvc_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	pvc_getname,
	.poll =		vcc_poll,
	.ioctl =	vcc_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = vcc_compat_ioctl,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,6 +95,7 @@
 		return -ENOTCONN;
 	*sockaddr_len = sizeof(struct sockaddr_atmpvc);
 	addr = (struct sockaddr_atmpvc *)sockaddr;
+	memset(addr, 0, sizeof(*addr));
 	addr->sap_family = AF_ATMPVC;
 	addr->sap_addr.itf = vcc->dev->number;
 	addr->sap_addr.vpi = vcc->vpi;
```
