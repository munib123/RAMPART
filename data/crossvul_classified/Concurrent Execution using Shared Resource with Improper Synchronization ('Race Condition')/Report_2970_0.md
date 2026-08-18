# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 2970_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2970_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 496-536 of the vulnerable file.


	offset -= rfv->hlen;

	return ip_generic_getfrag(rfv->msg, to, offset, len, odd, skb);
}

static int raw_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	struct flowi4 fl4;
	int free = 0;
	__be32 daddr;
	__be32 saddr;
	u8  tos;
	int err;
	struct ip_options_data opt_copy;
	struct raw_frag_vec rfv;

	err = -EMSGSIZE;
	if (len > 0xFFFF)
		goto out;

	/*
	 *	Check the flags.
	 */

	err = -EOPNOTSUPP;
	if (msg->msg_flags & MSG_OOB)	/* Mirror BSD error message */
		goto out;               /* compatibility */

	/*
	 *	Get and verify the address.
	 */

	if (msg->msg_namelen) {
		DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
		err = -EINVAL;
		if (msg->msg_namelen < sizeof(*usin))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -513,11 +513,16 @@
 	int err;
 	struct ip_options_data opt_copy;
 	struct raw_frag_vec rfv;
+	int hdrincl;
 
 	err = -EMSGSIZE;
 	if (len > 0xFFFF)
 		goto out;
 
+	/* hdrincl should be READ_ONCE(inet->hdrincl)
+	 * but READ_ONCE() doesn't work with bit fields
+	 */
+	hdrincl = inet->hdrincl;
 	/*
 	 *	Check the flags.
 	 */
@@ -593,7 +598,7 @@
 		/* Linux does not mangle headers on raw sockets,
 		 * so that IP options + IP_HDRINCL is non-sense.
 		 */
-		if (inet->hdrincl)
+		if (hdrincl)
 			goto done;
 		if (ipc.opt->opt.srr) {
 			if (!daddr)
@@ -615,12 +620,12 @@
 
 	flowi4_init_output(&fl4, ipc.oif, sk->sk_mark, tos,
 			   RT_SCOPE_UNIVERSE,
-			   inet->hdrincl ? IPPROTO_RAW : sk->sk_protocol,
+			   hdrincl ? IPPROTO_RAW : sk->sk_protocol,
 			   inet_sk_flowi_flags(sk) |
-			    (inet->hdrincl ? FLOWI_FLAG_KNOWN_NH : 0),
+			    (hdrincl ? FLOWI_FLAG_KNOWN_NH : 0),
 			   daddr, saddr, 0, 0, sk->sk_uid);
 
-	if (!inet->hdrincl) {
+	if (!hdrincl) {
 		rfv.msg = msg;
 		rfv.hlen = 0;
 
@@ -645,7 +650,7 @@
 		goto do_confirm;
 back_from_confirm:
 
-	if (inet->hdrincl)
+	if (hdrincl)
 		err = raw_send_hdrinc(sk, &fl4, msg, len,
 				      &rt, msg->msg_flags, &ipc.sockc);
 
```
