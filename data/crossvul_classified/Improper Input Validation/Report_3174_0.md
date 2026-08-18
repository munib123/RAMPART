# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3174_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3174_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 804-844 of the vulnerable file.

	 * method because of the way the PROCOM state machine works:
	 * it needs to set several state variables (see, for instance,
	 * llc_adm_actions_2 in net/llc/llc_c_st.c) and send a packet to
	 * the originator of the new connection, and this state has to be
	 * in the newly created struct sock private area. -acme
	 */
	if (unlikely(sk->sk_state == TCP_LISTEN)) {
		struct sock *newsk = llc_create_incoming_sock(sk, skb->dev,
							      &saddr, &daddr);
		if (!newsk)
			goto drop_unlock;
		skb_set_owner_r(skb, newsk);
	} else {
		/*
		 * Can't be skb_set_owner_r, this will be done at the
		 * llc_conn_state_process function, later on, when we will use
		 * skb_queue_rcv_skb to send it to upper layers, this is
		 * another trick required to cope with how the PROCOM state
		 * machine works. -acme
		 */
		skb->sk = sk;
	}
	if (!sock_owned_by_user(sk))
		llc_conn_rcv(sk, skb);
	else {
		dprintk("%s: adding to backlog...\n", __func__);
		llc_set_backlog_type(skb, LLC_PACKET);
		if (sk_add_backlog(sk, skb, sk->sk_rcvbuf))
			goto drop_unlock;
	}
out:
	bh_unlock_sock(sk);
	sock_put(sk);
	return;
drop:
	kfree_skb(skb);
	return;
drop_unlock:
	kfree_skb(skb);
	goto out;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -821,7 +821,10 @@
 		 * another trick required to cope with how the PROCOM state
 		 * machine works. -acme
 		 */
+		skb_orphan(skb);
+		sock_hold(sk);
 		skb->sk = sk;
+		skb->destructor = sock_efree;
 	}
 	if (!sock_owned_by_user(sk))
 		llc_conn_rcv(sk, skb);
```
