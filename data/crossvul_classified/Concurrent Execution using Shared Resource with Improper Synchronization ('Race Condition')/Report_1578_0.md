# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1578_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1578_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 14-54 of the vulnerable file.

#endif
#ifdef CONFIG_SYSCTL
	struct ctl_table_header *sysctl_header;
#endif
	/* This is the global socket data structure used for responding to
	 * the Out-of-the-blue (OOTB) packets.  A control sock will be created
	 * for this socket at the initialization time.
	 */
	struct sock *ctl_sock;

	/* This is the global local address list.
	 * We actively maintain this complete list of addresses on
	 * the system by catching address add/delete events.
	 *
	 * It is a list of sctp_sockaddr_entry.
	 */
	struct list_head local_addr_list;
	struct list_head addr_waitq;
	struct timer_list addr_wq_timer;
	struct list_head auto_asconf_splist;
	spinlock_t addr_wq_lock;

	/* Lock that protects the local_addr_list writers */
	spinlock_t local_addr_lock;

	/* RFC2960 Section 14. Suggested SCTP Protocol Parameter Values
	 *
	 * The following protocol parameters are RECOMMENDED:
	 *
	 * RTO.Initial		    - 3	 seconds
	 * RTO.Min		    - 1	 second
	 * RTO.Max		   -  60 seconds
	 * RTO.Alpha		    - 1/8  (3 when converted to right shifts.)
	 * RTO.Beta		    - 1/4  (2 when converted to right shifts.)
	 */
	unsigned int rto_initial;
	unsigned int rto_min;
	unsigned int rto_max;

	/* Note: rto_alpha and rto_beta are really defined as inverse
	 * powers of two to facilitate integer operations.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,7 @@
 	struct list_head addr_waitq;
 	struct timer_list addr_wq_timer;
 	struct list_head auto_asconf_splist;
+	/* Lock that protects both addr_waitq and auto_asconf_splist */
 	spinlock_t addr_wq_lock;
 
 	/* Lock that protects the local_addr_list writers */
```
