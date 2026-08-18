# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3254_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3254_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 689-729 of the vulnerable file.

			struct timespec ts;
			skb_get_timestampns(skb, &ts);
			put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMPNS,
				 sizeof(ts), &ts);
		}
	}

	memset(&tss, 0, sizeof(tss));
	if ((sk->sk_tsflags & SOF_TIMESTAMPING_SOFTWARE) &&
	    ktime_to_timespec_cond(skb->tstamp, tss.ts + 0))
		empty = 0;
	if (shhwtstamps &&
	    (sk->sk_tsflags & SOF_TIMESTAMPING_RAW_HARDWARE) &&
	    ktime_to_timespec_cond(shhwtstamps->hwtstamp, tss.ts + 2))
		empty = 0;
	if (!empty) {
		put_cmsg(msg, SOL_SOCKET,
			 SCM_TIMESTAMPING, sizeof(tss), &tss);

		if (skb_is_err_queue(skb) && skb->len &&
		    (sk->sk_tsflags & SOF_TIMESTAMPING_OPT_STATS))
			put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMPING_OPT_STATS,
				 skb->len, skb->data);
	}
}
EXPORT_SYMBOL_GPL(__sock_recv_timestamp);

void __sock_recv_wifi_status(struct msghdr *msg, struct sock *sk,
	struct sk_buff *skb)
{
	int ack;

	if (!sock_flag(sk, SOCK_WIFI_STATUS))
		return;
	if (!skb->wifi_acked_valid)
		return;

	ack = skb->wifi_acked;

	put_cmsg(msg, SOL_SOCKET, SCM_WIFI_STATUS, sizeof(ack), &ack);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -706,7 +706,7 @@
 			 SCM_TIMESTAMPING, sizeof(tss), &tss);
 
 		if (skb_is_err_queue(skb) && skb->len &&
-		    (sk->sk_tsflags & SOF_TIMESTAMPING_OPT_STATS))
+		    SKB_EXT_ERR(skb)->opt_stats)
 			put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMPING_OPT_STATS,
 				 skb->len, skb->data);
 	}
```
