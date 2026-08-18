# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5349_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5349_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 1203-1243 of the vulnerable file.

}

static inline bool tcp_checksum_complete(struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) &&
		__tcp_checksum_complete(skb);
}

/* Prequeue for VJ style copy to user, combined with checksumming. */

static inline void tcp_prequeue_init(struct tcp_sock *tp)
{
	tp->ucopy.task = NULL;
	tp->ucopy.len = 0;
	tp->ucopy.memory = 0;
	skb_queue_head_init(&tp->ucopy.prequeue);
}

bool tcp_prequeue(struct sock *sk, struct sk_buff *skb);
bool tcp_add_backlog(struct sock *sk, struct sk_buff *skb);

#undef STATE_TRACE

#ifdef STATE_TRACE
static const char *statename[]={
	"Unused","Established","Syn Sent","Syn Recv",
	"Fin Wait 1","Fin Wait 2","Time Wait", "Close",
	"Close Wait","Last ACK","Listen","Closing"
};
#endif
void tcp_set_state(struct sock *sk, int state);

void tcp_done(struct sock *sk);

int tcp_abort(struct sock *sk, int err);

static inline void tcp_sack_reset(struct tcp_options_received *rx_opt)
{
	rx_opt->dsack = 0;
	rx_opt->num_sacks = 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1220,6 +1220,7 @@
 
 bool tcp_prequeue(struct sock *sk, struct sk_buff *skb);
 bool tcp_add_backlog(struct sock *sk, struct sk_buff *skb);
+int tcp_filter(struct sock *sk, struct sk_buff *skb);
 
 #undef STATE_TRACE
 
```
