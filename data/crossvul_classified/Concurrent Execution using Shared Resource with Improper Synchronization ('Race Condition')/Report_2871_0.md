# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 2871_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2871_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1667-1710 of the vulnerable file.

	int err;

	switch (type) {
	case PACKET_FANOUT_ROLLOVER:
		if (type_flags & PACKET_FANOUT_FLAG_ROLLOVER)
			return -EINVAL;
	case PACKET_FANOUT_HASH:
	case PACKET_FANOUT_LB:
	case PACKET_FANOUT_CPU:
	case PACKET_FANOUT_RND:
	case PACKET_FANOUT_QM:
	case PACKET_FANOUT_CBPF:
	case PACKET_FANOUT_EBPF:
		break;
	default:
		return -EINVAL;
	}

	mutex_lock(&fanout_mutex);

	err = -EINVAL;
	if (!po->running)
		goto out;

	err = -EALREADY;
	if (po->fanout)
		goto out;

	if (type == PACKET_FANOUT_ROLLOVER ||
	    (type_flags & PACKET_FANOUT_FLAG_ROLLOVER)) {
		err = -ENOMEM;
		rollover = kzalloc(sizeof(*rollover), GFP_KERNEL);
		if (!rollover)
			goto out;
		atomic_long_set(&rollover->num, 0);
		atomic_long_set(&rollover->num_huge, 0);
		atomic_long_set(&rollover->num_failed, 0);
		po->rollover = rollover;
	}

	if (type_flags & PACKET_FANOUT_FLAG_UNIQUEID) {
		if (id != 0) {
			err = -EINVAL;
			goto out;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1684,10 +1684,6 @@
 
 	mutex_lock(&fanout_mutex);
 
-	err = -EINVAL;
-	if (!po->running)
-		goto out;
-
 	err = -EALREADY;
 	if (po->fanout)
 		goto out;
@@ -1749,7 +1745,10 @@
 		list_add(&match->list, &fanout_list);
 	}
 	err = -EINVAL;
-	if (match->type == type &&
+
+	spin_lock(&po->bind_lock);
+	if (po->running &&
+	    match->type == type &&
 	    match->prot_hook.type == po->prot_hook.type &&
 	    match->prot_hook.dev == po->prot_hook.dev) {
 		err = -ENOSPC;
@@ -1761,6 +1760,13 @@
 			err = 0;
 		}
 	}
+	spin_unlock(&po->bind_lock);
+
+	if (err && !refcount_read(&match->sk_ref)) {
+		list_del(&match->list);
+		kfree(match);
+	}
+
 out:
 	if (err && rollover) {
 		kfree(rollover);
```
