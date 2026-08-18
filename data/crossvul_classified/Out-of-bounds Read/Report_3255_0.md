# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3255_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3255_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 3677-3717 of the vulnerable file.

			*skb_p = skb2;
			kfree_skb(skb1);
			skb1 = skb2;
		}
		elt++;
		*trailer = skb1;
		skb_p = &skb1->next;
	}

	return elt;
}
EXPORT_SYMBOL_GPL(skb_cow_data);

static void sock_rmem_free(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
}

/*
 * Note: We dont mem charge error packets (no sk_forward_alloc changes)
 */
int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb)
{
	if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize >=
	    (unsigned int)sk->sk_rcvbuf)
		return -ENOMEM;

	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rmem_free;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);

	/* before exiting rcu section, make sure dst is refcounted */
	skb_dst_force(skb);

	skb_queue_tail(&sk->sk_error_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk);
	return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3694,6 +3694,15 @@
 	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
 }
 
+static void skb_set_err_queue(struct sk_buff *skb)
+{
+	/* pkt_type of skbs received on local sockets is never PACKET_OUTGOING.
+	 * So, it is safe to (mis)use it to mark skbs on the error queue.
+	 */
+	skb->pkt_type = PACKET_OUTGOING;
+	BUILD_BUG_ON(PACKET_OUTGOING == 0);
+}
+
 /*
  * Note: We dont mem charge error packets (no sk_forward_alloc changes)
  */
@@ -3707,6 +3716,7 @@
 	skb->sk = sk;
 	skb->destructor = sock_rmem_free;
 	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
+	skb_set_err_queue(skb);
 
 	/* before exiting rcu section, make sure dst is refcounted */
 	skb_dst_force(skb);
```
