# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2036_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2036_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1346-1386 of the vulnerable file.

	 * hold the references to key1.
	 */
	while (--drop_count >= 0)
		drop_futex_key_refs(&key1);

out_put_keys:
	put_futex_key(fshared, &key2);
out_put_key1:
	put_futex_key(fshared, &key1);
out:
	if (pi_state != NULL)
		free_pi_state(pi_state);
	return ret ? ret : task_count;
}

/* The key must be already stored in q->key. */
static inline struct futex_hash_bucket *queue_lock(struct futex_q *q)
{
	struct futex_hash_bucket *hb;

	get_futex_key_refs(&q->key);
	hb = hash_futex(&q->key);
	q->lock_ptr = &hb->lock;

	spin_lock(&hb->lock);
	return hb;
}

static inline void
queue_unlock(struct futex_q *q, struct futex_hash_bucket *hb)
{
	spin_unlock(&hb->lock);
	drop_futex_key_refs(&q->key);
}

/**
 * queue_me() - Enqueue the futex_q on the futex_hash_bucket
 * @q:	The futex_q to enqueue
 * @hb:	The destination hash bucket
 *
 * The hb->lock must be held by the caller, and is released here. A call to
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1363,7 +1363,6 @@
 {
 	struct futex_hash_bucket *hb;
 
-	get_futex_key_refs(&q->key);
 	hb = hash_futex(&q->key);
 	q->lock_ptr = &hb->lock;
 
@@ -1375,7 +1374,6 @@
 queue_unlock(struct futex_q *q, struct futex_hash_bucket *hb)
 {
 	spin_unlock(&hb->lock);
-	drop_futex_key_refs(&q->key);
 }
 
 /**
@@ -1480,8 +1478,6 @@
 	q->pi_state = NULL;
 
 	spin_unlock(q->lock_ptr);
-
-	drop_futex_key_refs(&q->key);
 }
 
 /*
@@ -1812,7 +1808,10 @@
 	}
 
 retry:
-	/* Prepare to wait on uaddr. */
+	/*
+	 * Prepare to wait on uaddr. On success, holds hb lock and increments
+	 * q.key refs.
+	 */
 	ret = futex_wait_setup(uaddr, val, fshared, &q, &hb);
 	if (ret)
 		goto out;
@@ -1822,24 +1821,23 @@
 
 	/* If we were woken (and unqueued), we succeeded, whatever. */
 	ret = 0;
+	/* unqueue_me() drops q.key ref */
 	if (!unqueue_me(&q))
-		goto out_put_key;
+		goto out;
 	ret = -ETIMEDOUT;
 	if (to && !to->task)
-		goto out_put_key;
+		goto out;
 
 	/*
 	 * We expect signal_pending(current), but we might be the
 	 * victim of a spurious wakeup as well.
 	 */
-	if (!signal_pending(current)) {
-		put_futex_key(fshared, &q.key);
+	if (!signal_pending(current))
 		goto retry;
-	}
 
 	ret = -ERESTARTSYS;
 	if (!abs_time)
-		goto out_put_key;
+		goto out;
 
 	restart = &current_thread_info()->restart_block;
 	restart->fn = futex_wait_restart;
@@ -1856,8 +1854,6 @@
 
 	ret = -ERESTART_RESTARTBLOCK;
 
-out_put_key:
-	put_futex_key(fshared, &q.key);
 out:
 	if (to) {
 		hrtimer_cancel(&to->timer);
@@ -2236,7 +2232,10 @@
 	q.rt_waiter = &rt_waiter;
 	q.requeue_pi_key = &key2;
 
-	/* Prepare to wait on uaddr. */
+	/*
+	 * Prepare to wait on uaddr. On success, increments q.key (key1) ref
+	 * count.
+	 */
 	ret = futex_wait_setup(uaddr, val, fshared, &q, &hb);
 	if (ret)
 		goto out_key2;
@@ -2254,7 +2253,9 @@
 	 * In order for us to be here, we know our q.key == key2, and since
 	 * we took the hb->lock above, we also know that futex_requeue() has
 	 * completed and we no longer have to concern ourselves with a wakeup
-	 * race with the atomic proxy lock acquition by the requeue code.
+	 * race with the atomic proxy lock acquisition by the requeue code. The
+	 * futex_requeue dropped our key1 reference and incremented our key2
+	 * reference count.
 	 */
 
 	/* Check if the requeue code acquired the second futex for us. */
```
