# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1865_3
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1865_3`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 542-588 of the vulnerable file.

void blk_mq_abort_requeue_list(struct request_queue *q)
{
	unsigned long flags;
	LIST_HEAD(rq_list);

	spin_lock_irqsave(&q->requeue_lock, flags);
	list_splice_init(&q->requeue_list, &rq_list);
	spin_unlock_irqrestore(&q->requeue_lock, flags);

	while (!list_empty(&rq_list)) {
		struct request *rq;

		rq = list_first_entry(&rq_list, struct request, queuelist);
		list_del_init(&rq->queuelist);
		rq->errors = -EIO;
		blk_mq_end_request(rq, rq->errors);
	}
}
EXPORT_SYMBOL(blk_mq_abort_requeue_list);

static inline bool is_flush_request(struct request *rq,
		struct blk_flush_queue *fq, unsigned int tag)
{
	return ((rq->cmd_flags & REQ_FLUSH_SEQ) &&
			fq->flush_rq->tag == tag);
}

struct request *blk_mq_tag_to_rq(struct blk_mq_tags *tags, unsigned int tag)
{
	struct request *rq = tags->rqs[tag];
	/* mq_ctx of flush rq is always cloned from the corresponding req */
	struct blk_flush_queue *fq = blk_get_flush_queue(rq->q, rq->mq_ctx);

	if (!is_flush_request(rq, fq, tag))
		return rq;

	return fq->flush_rq;
}
EXPORT_SYMBOL(blk_mq_tag_to_rq);

struct blk_mq_timeout_data {
	unsigned long next;
	unsigned int next_set;
};

void blk_mq_rq_timed_out(struct request *req, bool reserved)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -559,23 +559,9 @@
 }
 EXPORT_SYMBOL(blk_mq_abort_requeue_list);
 
-static inline bool is_flush_request(struct request *rq,
-		struct blk_flush_queue *fq, unsigned int tag)
-{
-	return ((rq->cmd_flags & REQ_FLUSH_SEQ) &&
-			fq->flush_rq->tag == tag);
-}
-
 struct request *blk_mq_tag_to_rq(struct blk_mq_tags *tags, unsigned int tag)
 {
-	struct request *rq = tags->rqs[tag];
-	/* mq_ctx of flush rq is always cloned from the corresponding req */
-	struct blk_flush_queue *fq = blk_get_flush_queue(rq->q, rq->mq_ctx);
-
-	if (!is_flush_request(rq, fq, tag))
-		return rq;
-
-	return fq->flush_rq;
+	return tags->rqs[tag];
 }
 EXPORT_SYMBOL(blk_mq_tag_to_rq);
 
```
