# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 4961_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4961_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 125-165 of the vulnerable file.

	q->timer = snd_seq_timer_new();
	if (q->tickq == NULL || q->timeq == NULL || q->timer == NULL) {
		snd_seq_prioq_delete(&q->tickq);
		snd_seq_prioq_delete(&q->timeq);
		snd_seq_timer_delete(&q->timer);
		kfree(q);
		return NULL;
	}

	q->owner = owner;
	q->locked = locked;
	q->klocked = 0;

	return q;
}

/* delete queue (destructor) */
static void queue_delete(struct snd_seq_queue *q)
{
	/* stop and release the timer */
	snd_seq_timer_stop(q->timer);
	snd_seq_timer_close(q);
	/* wait until access free */
	snd_use_lock_sync(&q->use_lock);
	/* release resources... */
	snd_seq_prioq_delete(&q->tickq);
	snd_seq_prioq_delete(&q->timeq);
	snd_seq_timer_delete(&q->timer);

	kfree(q);
}


/*----------------------------------------------------------------*/

/* setup queues */
int __init snd_seq_queues_init(void)
{
	/*
	memset(queue_list, 0, sizeof(queue_list));
	num_queues = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,8 +142,10 @@
 static void queue_delete(struct snd_seq_queue *q)
 {
 	/* stop and release the timer */
+	mutex_lock(&q->timer_mutex);
 	snd_seq_timer_stop(q->timer);
 	snd_seq_timer_close(q);
+	mutex_unlock(&q->timer_mutex);
 	/* wait until access free */
 	snd_use_lock_sync(&q->use_lock);
 	/* release resources... */
```
