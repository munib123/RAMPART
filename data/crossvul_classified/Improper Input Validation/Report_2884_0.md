# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2884_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2884_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 516-556 of the vulnerable file.

	conn = l2cap_pi(session->sock->sk)->chan->conn->hcon;
	if (!conn)
		return NULL;

	return &conn->dev;
}

static struct device_type bnep_type = {
	.name	= "bluetooth",
};

int bnep_add_connection(struct bnep_connadd_req *req, struct socket *sock)
{
	struct net_device *dev;
	struct bnep_session *s, *ss;
	u8 dst[ETH_ALEN], src[ETH_ALEN];
	int err;

	BT_DBG("");

	baswap((void *) dst, &l2cap_pi(sock->sk)->chan->dst);
	baswap((void *) src, &l2cap_pi(sock->sk)->chan->src);

	/* session struct allocated as private part of net_device */
	dev = alloc_netdev(sizeof(struct bnep_session),
			   (*req->device) ? req->device : "bnep%d",
			   NET_NAME_UNKNOWN,
			   bnep_net_setup);
	if (!dev)
		return -ENOMEM;

	down_write(&bnep_session_sem);

	ss = __bnep_get_session(dst);
	if (ss && ss->state == BT_CONNECTED) {
		err = -EEXIST;
		goto failed;
	}

	s = netdev_priv(dev);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -533,6 +533,9 @@
 
 	BT_DBG("");
 
+	if (!l2cap_is_socket(sock))
+		return -EBADFD;
+
 	baswap((void *) dst, &l2cap_pi(sock->sk)->chan->dst);
 	baswap((void *) src, &l2cap_pi(sock->sk)->chan->src);
 
```
