# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3037_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3037_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 765-805 of the vulnerable file.

	}
	spin_unlock_irqrestore(&queue->qlock, flags);

	flush_workqueue(queue->work_q);

	if (disconnect)
		nvmet_sq_destroy(&queue->nvme_sq);

	nvmet_fc_tgt_q_put(queue);
}

static struct nvmet_fc_tgt_queue *
nvmet_fc_find_target_queue(struct nvmet_fc_tgtport *tgtport,
				u64 connection_id)
{
	struct nvmet_fc_tgt_assoc *assoc;
	struct nvmet_fc_tgt_queue *queue;
	u64 association_id = nvmet_fc_getassociationid(connection_id);
	u16 qid = nvmet_fc_getqueueid(connection_id);
	unsigned long flags;

	spin_lock_irqsave(&tgtport->lock, flags);
	list_for_each_entry(assoc, &tgtport->assoc_list, a_list) {
		if (association_id == assoc->association_id) {
			queue = assoc->queues[qid];
			if (queue &&
			    (!atomic_read(&queue->connected) ||
			     !nvmet_fc_tgt_q_get(queue)))
				queue = NULL;
			spin_unlock_irqrestore(&tgtport->lock, flags);
			return queue;
		}
	}
	spin_unlock_irqrestore(&tgtport->lock, flags);
	return NULL;
}

static struct nvmet_fc_tgt_assoc *
nvmet_fc_alloc_target_assoc(struct nvmet_fc_tgtport *tgtport)
{
	struct nvmet_fc_tgt_assoc *assoc, *tmpassoc;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -782,6 +782,9 @@
 	u64 association_id = nvmet_fc_getassociationid(connection_id);
 	u16 qid = nvmet_fc_getqueueid(connection_id);
 	unsigned long flags;
+
+	if (qid > NVMET_NR_QUEUES)
+		return NULL;
 
 	spin_lock_irqsave(&tgtport->lock, flags);
 	list_for_each_entry(assoc, &tgtport->assoc_list, a_list) {
```
