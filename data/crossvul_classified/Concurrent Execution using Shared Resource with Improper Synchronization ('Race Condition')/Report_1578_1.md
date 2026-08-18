# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1578_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1578_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 206-246 of the vulnerable file.

	struct sctp_rtoinfo rtoinfo;
	struct sctp_paddrparams paddrparam;
	struct sctp_event_subscribe subscribe;
	struct sctp_assocparams assocparams;

	int user_frag;

	__u32 autoclose;
	__u8 nodelay;
	__u8 disable_fragments;
	__u8 v4mapped;
	__u8 frag_interleave;
	__u32 adaptation_ind;
	__u32 pd_point;
	__u8 recvrcvinfo;
	__u8 recvnxtinfo;

	atomic_t pd_mode;
	/* Receive to here while partial delivery is in effect. */
	struct sk_buff_head pd_lobby;
	struct list_head auto_asconf_list;
	int do_auto_asconf;
};

static inline struct sctp_sock *sctp_sk(const struct sock *sk)
{
       return (struct sctp_sock *)sk;
}

static inline struct sock *sctp_opt2sk(const struct sctp_sock *sp)
{
       return (struct sock *)sp;
}

#if IS_ENABLED(CONFIG_IPV6)
struct sctp6_sock {
       struct sctp_sock  sctp;
       struct ipv6_pinfo inet6;
};
#endif /* CONFIG_IPV6 */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -223,6 +223,10 @@
 	atomic_t pd_mode;
 	/* Receive to here while partial delivery is in effect. */
 	struct sk_buff_head pd_lobby;
+
+	/* These must be the last fields, as they will skipped on copies,
+	 * like on accept and peeloff operations
+	 */
 	struct list_head auto_asconf_list;
 	int do_auto_asconf;
 };
```
