# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1803_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1803_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 227-267 of the vulnerable file.


		/* Stop the SACK timer.  */
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP,
				SCTP_TO(SCTP_EVENT_TIMEOUT_SACK));
	}

	return error;
nomem:
	error = -ENOMEM;
	return error;
}

/* When the T3-RTX timer expires, it calls this function to create the
 * relevant state machine event.
 */
void sctp_generate_t3_rtx_event(unsigned long peer)
{
	int error;
	struct sctp_transport *transport = (struct sctp_transport *) peer;
	struct sctp_association *asoc = transport->asoc;
	struct net *net = sock_net(asoc->base.sk);

	/* Check whether a task is in the sock.  */

	bh_lock_sock(asoc->base.sk);
	if (sock_owned_by_user(asoc->base.sk)) {
		pr_debug("%s: sock is busy\n", __func__);

		/* Try again later.  */
		if (!mod_timer(&transport->T3_rtx_timer, jiffies + (HZ/20)))
			sctp_transport_hold(transport);
		goto out_unlock;
	}

	/* Is this transport really dead and just waiting around for
	 * the timer to let go of the reference?
	 */
	if (transport->dead)
		goto out_unlock;

	/* Run through the state machine.  */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -244,12 +244,13 @@
 	int error;
 	struct sctp_transport *transport = (struct sctp_transport *) peer;
 	struct sctp_association *asoc = transport->asoc;
-	struct net *net = sock_net(asoc->base.sk);
+	struct sock *sk = asoc->base.sk;
+	struct net *net = sock_net(sk);
 
 	/* Check whether a task is in the sock.  */
 
-	bh_lock_sock(asoc->base.sk);
-	if (sock_owned_by_user(asoc->base.sk)) {
+	bh_lock_sock(sk);
+	if (sock_owned_by_user(sk)) {
 		pr_debug("%s: sock is busy\n", __func__);
 
 		/* Try again later.  */
@@ -272,10 +273,10 @@
 			   transport, GFP_ATOMIC);
 
 	if (error)
-		asoc->base.sk->sk_err = -error;
+		sk->sk_err = -error;
 
 out_unlock:
-	bh_unlock_sock(asoc->base.sk);
+	bh_unlock_sock(sk);
 	sctp_transport_put(transport);
 }
 
@@ -285,11 +286,12 @@
 static void sctp_generate_timeout_event(struct sctp_association *asoc,
 					sctp_event_timeout_t timeout_type)
 {
-	struct net *net = sock_net(asoc->base.sk);
+	struct sock *sk = asoc->base.sk;
+	struct net *net = sock_net(sk);
 	int error = 0;
 
-	bh_lock_sock(asoc->base.sk);
-	if (sock_owned_by_user(asoc->base.sk)) {
+	bh_lock_sock(sk);
+	if (sock_owned_by_user(sk)) {
 		pr_debug("%s: sock is busy: timer %d\n", __func__,
 			 timeout_type);
 
@@ -312,10 +314,10 @@
 			   (void *)timeout_type, GFP_ATOMIC);
 
 	if (error)
-		asoc->base.sk->sk_err = -error;
+		sk->sk_err = -error;
 
 out_unlock:
-	bh_unlock_sock(asoc->base.sk);
+	bh_unlock_sock(sk);
 	sctp_association_put(asoc);
 }
 
@@ -365,10 +367,11 @@
 	int error = 0;
 	struct sctp_transport *transport = (struct sctp_transport *) data;
 	struct sctp_association *asoc = transport->asoc;
-	struct net *net = sock_net(asoc->base.sk);
-
-	bh_lock_sock(asoc->base.sk);
-	if (sock_owned_by_user(asoc->base.sk)) {
+	struct sock *sk = asoc->base.sk;
+	struct net *net = sock_net(sk);
+
+	bh_lock_sock(sk);
+	if (sock_owned_by_user(sk)) {
 		pr_debug("%s: sock is busy\n", __func__);
 
 		/* Try again later.  */
@@ -389,10 +392,10 @@
 			   transport, GFP_ATOMIC);
 
 	if (error)
-		asoc->base.sk->sk_err = -error;
+		sk->sk_err = -error;
 
 out_unlock:
-	bh_unlock_sock(asoc->base.sk);
+	bh_unlock_sock(sk);
 	sctp_transport_put(transport);
 }
 
@@ -403,10 +406,11 @@
 {
 	struct sctp_transport *transport = (struct sctp_transport *) data;
 	struct sctp_association *asoc = transport->asoc;
-	struct net *net = sock_net(asoc->base.sk);
-
-	bh_lock_sock(asoc->base.sk);
-	if (sock_owned_by_user(asoc->base.sk)) {
+	struct sock *sk = asoc->base.sk;
+	struct net *net = sock_net(sk);
+
+	bh_lock_sock(sk);
+	if (sock_owned_by_user(sk)) {
 		pr_debug("%s: sock is busy\n", __func__);
 
 		/* Try again later.  */
@@ -427,7 +431,7 @@
 		   asoc->state, asoc->ep, asoc, transport, GFP_ATOMIC);
 
 out_unlock:
-	bh_unlock_sock(asoc->base.sk);
+	bh_unlock_sock(sk);
 	sctp_association_put(asoc);
 }
 
```
