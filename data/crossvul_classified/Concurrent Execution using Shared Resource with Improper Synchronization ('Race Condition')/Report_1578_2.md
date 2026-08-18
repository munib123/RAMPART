# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1578_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1578_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1511-1551 of the vulnerable file.

		    !skb_queue_empty(&asoc->ulpq.reasm) ||
		    (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime)) {
			struct sctp_chunk *chunk;

			chunk = sctp_make_abort_user(asoc, NULL, 0);
			if (chunk)
				sctp_primitive_ABORT(net, asoc, chunk);
		} else
			sctp_primitive_SHUTDOWN(net, asoc, NULL);
	}

	/* On a TCP-style socket, block for at most linger_time if set. */
	if (sctp_style(sk, TCP) && timeout)
		sctp_wait_for_close(sk, timeout);

	/* This will run the backlog queue.  */
	release_sock(sk);

	/* Supposedly, no process has access to the socket, but
	 * the net layers still may.
	 */
	local_bh_disable();
	bh_lock_sock(sk);

	/* Hold the sock, since sk_common_release() will put sock_put()
	 * and we have just a little more cleanup.
	 */
	sock_hold(sk);
	sk_common_release(sk);

	bh_unlock_sock(sk);
	local_bh_enable();

	sock_put(sk);

	SCTP_DBG_OBJCNT_DEC(sock);
}

/* Handle EPIPE error. */
static int sctp_error(struct sock *sk, int flags, int err)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1528,8 +1528,10 @@
 
 	/* Supposedly, no process has access to the socket, but
 	 * the net layers still may.
-	 */
-	local_bh_disable();
+	 * Also, sctp_destroy_sock() needs to be called with addr_wq_lock
+	 * held and that should be grabbed before socket lock.
+	 */
+	spin_lock_bh(&net->sctp.addr_wq_lock);
 	bh_lock_sock(sk);
 
 	/* Hold the sock, since sk_common_release() will put sock_put()
@@ -1539,7 +1541,7 @@
 	sk_common_release(sk);
 
 	bh_unlock_sock(sk);
-	local_bh_enable();
+	spin_unlock_bh(&net->sctp.addr_wq_lock);
 
 	sock_put(sk);
 
@@ -3580,6 +3582,7 @@
 	if ((val && sp->do_auto_asconf) || (!val && !sp->do_auto_asconf))
 		return 0;
 
+	spin_lock_bh(&sock_net(sk)->sctp.addr_wq_lock);
 	if (val == 0 && sp->do_auto_asconf) {
 		list_del(&sp->auto_asconf_list);
 		sp->do_auto_asconf = 0;
@@ -3588,6 +3591,7 @@
 		    &sock_net(sk)->sctp.auto_asconf_splist);
 		sp->do_auto_asconf = 1;
 	}
+	spin_unlock_bh(&sock_net(sk)->sctp.addr_wq_lock);
 	return 0;
 }
 
@@ -4121,18 +4125,28 @@
 	local_bh_disable();
 	percpu_counter_inc(&sctp_sockets_allocated);
 	sock_prot_inuse_add(net, sk->sk_prot, 1);
+
+	/* Nothing can fail after this block, otherwise
+	 * sctp_destroy_sock() will be called without addr_wq_lock held
+	 */
 	if (net->sctp.default_auto_asconf) {
+		spin_lock(&sock_net(sk)->sctp.addr_wq_lock);
 		list_add_tail(&sp->auto_asconf_list,
 		    &net->sctp.auto_asconf_splist);
 		sp->do_auto_asconf = 1;
-	} else
+		spin_unlock(&sock_net(sk)->sctp.addr_wq_lock);
+	} else {
 		sp->do_auto_asconf = 0;
+	}
+
 	local_bh_enable();
 
 	return 0;
 }
 
-/* Cleanup any SCTP per socket resources.  */
+/* Cleanup any SCTP per socket resources. Must be called with
+ * sock_net(sk)->sctp.addr_wq_lock held if sp->do_auto_asconf is true
+ */
 static void sctp_destroy_sock(struct sock *sk)
 {
 	struct sctp_sock *sp;
@@ -7195,6 +7209,19 @@
 	newinet->mc_list = NULL;
 }
 
+static inline void sctp_copy_descendant(struct sock *sk_to,
+					const struct sock *sk_from)
+{
+	int ancestor_size = sizeof(struct inet_sock) +
+			    sizeof(struct sctp_sock) -
+			    offsetof(struct sctp_sock, auto_asconf_list);
+
+	if (sk_from->sk_family == PF_INET6)
+		ancestor_size += sizeof(struct ipv6_pinfo);
+
+	__inet_sk_copy_descendant(sk_to, sk_from, ancestor_size);
+}
+
 /* Populate the fields of the newsk from the oldsk and migrate the assoc
  * and its messages to the newsk.
  */
@@ -7209,7 +7236,6 @@
 	struct sk_buff *skb, *tmp;
 	struct sctp_ulpevent *event;
 	struct sctp_bind_hashbucket *head;
-	struct list_head tmplist;
 
 	/* Migrate socket buffer sizes and all the socket level options to the
 	 * new socket.
@@ -7217,12 +7243,7 @@
 	newsk->sk_sndbuf = oldsk->sk_sndbuf;
 	newsk->sk_rcvbuf = oldsk->sk_rcvbuf;
 	/* Brute force copy old sctp opt. */
-	if (oldsp->do_auto_asconf) {
-		memcpy(&tmplist, &newsp->auto_asconf_list, sizeof(tmplist));
-		inet_sk_copy_descendant(newsk, oldsk);
-		memcpy(&newsp->auto_asconf_list, &tmplist, sizeof(tmplist));
-	} else
-		inet_sk_copy_descendant(newsk, oldsk);
+	sctp_copy_descendant(newsk, oldsk);
 
 	/* Restore the ep value that was overwritten with the above structure
 	 * copy.
```
