# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3536_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3536_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 231-271 of the vulnerable file.

		goto discard_release;
	SCTP_INPUT_CB(skb)->chunk = chunk;

	/* Remember what endpoint is to handle this packet. */
	chunk->rcvr = rcvr;

	/* Remember the SCTP header. */
	chunk->sctp_hdr = sh;

	/* Set the source and destination addresses of the incoming chunk.  */
	sctp_init_addrs(chunk, &src, &dest);

	/* Remember where we came from.  */
	chunk->transport = transport;

	/* Acquire access to the sock lock. Note: We are safe from other
	 * bottom halves on this lock, but a user may be in the lock too,
	 * so check if it is busy.
	 */
	sctp_bh_lock_sock(sk);

	if (sock_owned_by_user(sk)) {
		SCTP_INC_STATS_BH(SCTP_MIB_IN_PKT_BACKLOG);
		sctp_add_backlog(sk, skb);
	} else {
		SCTP_INC_STATS_BH(SCTP_MIB_IN_PKT_SOFTIRQ);
		sctp_inq_push(&chunk->rcvr->inqueue, chunk);
	}

	sctp_bh_unlock_sock(sk);

	/* Release the asoc/ep ref we took in the lookup calls. */
	if (asoc)
		sctp_association_put(asoc);
	else
		sctp_endpoint_put(ep);

	return 0;

discard_it:
	SCTP_INC_STATS_BH(SCTP_MIB_IN_PKT_DISCARDS);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -248,6 +248,19 @@
 	 * so check if it is busy.
 	 */
 	sctp_bh_lock_sock(sk);
+
+	if (sk != rcvr->sk) {
+		/* Our cached sk is different from the rcvr->sk.  This is
+		 * because migrate()/accept() may have moved the association
+		 * to a new socket and released all the sockets.  So now we
+		 * are holding a lock on the old socket while the user may
+		 * be doing something with the new socket.  Switch our veiw
+		 * of the current sk.
+		 */
+		sctp_bh_unlock_sock(sk);
+		sk = rcvr->sk;
+		sctp_bh_lock_sock(sk);
+	}
 
 	if (sock_owned_by_user(sk)) {
 		SCTP_INC_STATS_BH(SCTP_MIB_IN_PKT_BACKLOG);
```
