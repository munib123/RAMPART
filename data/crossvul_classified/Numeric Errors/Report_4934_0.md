# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 4934_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4934_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 2460-2500 of the vulnerable file.

	struct tcp_sock *tp = tcp_sk(sk);

	tp->high_seq = tp->snd_nxt;
	tp->tlp_high_seq = 0;
	tp->snd_cwnd_cnt = 0;
	tp->prior_cwnd = tp->snd_cwnd;
	tp->prr_delivered = 0;
	tp->prr_out = 0;
	tp->snd_ssthresh = inet_csk(sk)->icsk_ca_ops->ssthresh(sk);
	tcp_ecn_queue_cwr(tp);
}

static void tcp_cwnd_reduction(struct sock *sk, const int prior_unsacked,
			       int fast_rexmit, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int sndcnt = 0;
	int delta = tp->snd_ssthresh - tcp_packets_in_flight(tp);
	int newly_acked_sacked = prior_unsacked -
				 (tp->packets_out - tp->sacked_out);

	tp->prr_delivered += newly_acked_sacked;
	if (delta < 0) {
		u64 dividend = (u64)tp->snd_ssthresh * tp->prr_delivered +
			       tp->prior_cwnd - 1;
		sndcnt = div_u64(dividend, tp->prior_cwnd) - tp->prr_out;
	} else if ((flag & FLAG_RETRANS_DATA_ACKED) &&
		   !(flag & FLAG_LOST_RETRANS)) {
		sndcnt = min_t(int, delta,
			       max_t(int, tp->prr_delivered - tp->prr_out,
				     newly_acked_sacked) + 1);
	} else {
		sndcnt = min(delta, newly_acked_sacked);
	}
	sndcnt = max(sndcnt, (fast_rexmit ? 1 : 0));
	tp->snd_cwnd = tcp_packets_in_flight(tp) + sndcnt;
}

static inline void tcp_end_cwnd_reduction(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2477,6 +2477,9 @@
 	int delta = tp->snd_ssthresh - tcp_packets_in_flight(tp);
 	int newly_acked_sacked = prior_unsacked -
 				 (tp->packets_out - tp->sacked_out);
+
+	if (newly_acked_sacked <= 0 || WARN_ON_ONCE(!tp->prior_cwnd))
+		return;
 
 	tp->prr_delivered += newly_acked_sacked;
 	if (delta < 0) {
```
