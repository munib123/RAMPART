# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5749_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5749_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 755-795 of the vulnerable file.

	if ((skb = skb_peek_tail(queue)) == NULL) {
		skb = sock_alloc_send_skb(sk,
			hh_len + fragheaderlen + transhdrlen + 20,
			(flags & MSG_DONTWAIT), &err);

		if (skb == NULL)
			return err;

		/* reserve space for Hardware header */
		skb_reserve(skb, hh_len);

		/* create space for UDP/IP header */
		skb_put(skb, fragheaderlen + transhdrlen);

		/* initialize network header pointer */
		skb_reset_network_header(skb);

		/* initialize protocol header pointer */
		skb->transport_header = skb->network_header + fragheaderlen;

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum = 0;

		/* specify the length of each IP datagram fragment */
		skb_shinfo(skb)->gso_size = maxfraglen - fragheaderlen;
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
		__skb_queue_tail(queue, skb);
	}

	return skb_append_datato_frags(sk, skb, getfrag, from,
				       (length - transhdrlen));
}

static int __ip_append_data(struct sock *sk,
			    struct flowi4 *fl4,
			    struct sk_buff_head *queue,
			    struct inet_cork *cork,
			    struct page_frag *pfrag,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -772,15 +772,20 @@
 		/* initialize protocol header pointer */
 		skb->transport_header = skb->network_header + fragheaderlen;
 
-		skb->ip_summed = CHECKSUM_PARTIAL;
 		skb->csum = 0;
 
-		/* specify the length of each IP datagram fragment */
-		skb_shinfo(skb)->gso_size = maxfraglen - fragheaderlen;
-		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
+
 		__skb_queue_tail(queue, skb);
-	}
-
+	} else if (skb_is_gso(skb)) {
+		goto append;
+	}
+
+	skb->ip_summed = CHECKSUM_PARTIAL;
+	/* specify the length of each IP datagram fragment */
+	skb_shinfo(skb)->gso_size = maxfraglen - fragheaderlen;
+	skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
+
+append:
 	return skb_append_datato_frags(sk, skb, getfrag, from,
 				       (length - transhdrlen));
 }
```
