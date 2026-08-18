# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1757_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1757_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 220-260 of the vulnerable file.

int ipc_addid(struct ipc_ids *ids, struct kern_ipc_perm *new, int size)
{
	kuid_t euid;
	kgid_t egid;
	int id;
	int next_id = ids->next_id;

	if (size > IPCMNI)
		size = IPCMNI;

	if (ids->in_use >= size)
		return -ENOSPC;

	idr_preload(GFP_KERNEL);

	spin_lock_init(&new->lock);
	new->deleted = false;
	rcu_read_lock();
	spin_lock(&new->lock);

	id = idr_alloc(&ids->ipcs_idr, new,
		       (next_id < 0) ? 0 : ipcid_to_idx(next_id), 0,
		       GFP_NOWAIT);
	idr_preload_end();
	if (id < 0) {
		spin_unlock(&new->lock);
		rcu_read_unlock();
		return id;
	}

	ids->in_use++;

	current_euid_egid(&euid, &egid);
	new->cuid = new->uid = euid;
	new->gid = new->cgid = egid;

	if (next_id < 0) {
		new->seq = ids->seq++;
		if (ids->seq > IPCID_SEQ_MAX)
			ids->seq = 0;
	} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -237,6 +237,10 @@
 	rcu_read_lock();
 	spin_lock(&new->lock);
 
+	current_euid_egid(&euid, &egid);
+	new->cuid = new->uid = euid;
+	new->gid = new->cgid = egid;
+
 	id = idr_alloc(&ids->ipcs_idr, new,
 		       (next_id < 0) ? 0 : ipcid_to_idx(next_id), 0,
 		       GFP_NOWAIT);
@@ -248,10 +252,6 @@
 	}
 
 	ids->in_use++;
-
-	current_euid_egid(&euid, &egid);
-	new->cuid = new->uid = euid;
-	new->gid = new->cgid = egid;
 
 	if (next_id < 0) {
 		new->seq = ids->seq++;
```
