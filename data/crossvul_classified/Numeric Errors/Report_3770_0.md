# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3770_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3770_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 296-336 of the vulnerable file.

	struct tcp_sock *tp = tcp_sk(sk);
	struct illinois *ca = inet_csk_ca(sk);

	/* Multiplicative decrease */
	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->beta) >> BETA_SHIFT), 2U);
}


/* Extract info for Tcp socket info provided via netlink. */
static void tcp_illinois_info(struct sock *sk, u32 ext,
			      struct sk_buff *skb)
{
	const struct illinois *ca = inet_csk_ca(sk);

	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcpvegas_info info = {
			.tcpv_enabled = 1,
			.tcpv_rttcnt = ca->cnt_rtt,
			.tcpv_minrtt = ca->base_rtt,
		};
		u64 t = ca->sum_rtt;

		do_div(t, ca->cnt_rtt);
		info.tcpv_rtt = t;

		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
	}
}

static struct tcp_congestion_ops tcp_illinois __read_mostly = {
	.flags		= TCP_CONG_RTT_STAMP,
	.init		= tcp_illinois_init,
	.ssthresh	= tcp_illinois_ssthresh,
	.min_cwnd	= tcp_reno_min_cwnd,
	.cong_avoid	= tcp_illinois_cong_avoid,
	.set_state	= tcp_illinois_state,
	.get_info	= tcp_illinois_info,
	.pkts_acked	= tcp_illinois_acked,

	.owner		= THIS_MODULE,
	.name		= "illinois",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -313,11 +313,13 @@
 			.tcpv_rttcnt = ca->cnt_rtt,
 			.tcpv_minrtt = ca->base_rtt,
 		};
-		u64 t = ca->sum_rtt;
-
-		do_div(t, ca->cnt_rtt);
-		info.tcpv_rtt = t;
-
+
+		if (info.tcpv_rttcnt > 0) {
+			u64 t = ca->sum_rtt;
+
+			do_div(t, info.tcpv_rttcnt);
+			info.tcpv_rtt = t;
+		}
 		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
 	}
 }
```
