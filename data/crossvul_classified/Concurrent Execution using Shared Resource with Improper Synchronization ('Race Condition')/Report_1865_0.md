# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1865_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1865_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 56-96 of the vulnerable file.

 * Once while executing DATA and again after the whole sequence is
 * complete.  The first completion updates the contained bio but doesn't
 * finish it so that the bio submitter is notified only after the whole
 * sequence is complete.  This is implemented by testing REQ_FLUSH_SEQ in
 * req_bio_endio().
 *
 * The above peculiarity requires that each FLUSH/FUA request has only one
 * bio attached to it, which is guaranteed as they aren't allowed to be
 * merged in the usual way.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/gfp.h>
#include <linux/blk-mq.h>

#include "blk.h"
#include "blk-mq.h"

/* FLUSH/FUA sequences */
enum {
	REQ_FSEQ_PREFLUSH	= (1 << 0), /* pre-flushing in progress */
	REQ_FSEQ_DATA		= (1 << 1), /* data write in progress */
	REQ_FSEQ_POSTFLUSH	= (1 << 2), /* post-flushing in progress */
	REQ_FSEQ_DONE		= (1 << 3),

	REQ_FSEQ_ACTIONS	= REQ_FSEQ_PREFLUSH | REQ_FSEQ_DATA |
				  REQ_FSEQ_POSTFLUSH,

	/*
	 * If flush has been pending longer than the following timeout,
	 * it's issued even if flush_data requests are still in flight.
	 */
	FLUSH_PENDING_TIMEOUT	= 5 * HZ,
};

static bool blk_kick_flush(struct request_queue *q,
			   struct blk_flush_queue *fq);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,6 +73,7 @@
 
 #include "blk.h"
 #include "blk-mq.h"
+#include "blk-mq-tag.h"
 
 /* FLUSH/FUA sequences */
 enum {
@@ -226,7 +227,12 @@
 	struct blk_flush_queue *fq = blk_get_flush_queue(q, flush_rq->mq_ctx);
 
 	if (q->mq_ops) {
+		struct blk_mq_hw_ctx *hctx;
+
+		/* release the tag's ownership to the req cloned from */
 		spin_lock_irqsave(&fq->mq_flush_lock, flags);
+		hctx = q->mq_ops->map_queue(q, flush_rq->mq_ctx->cpu);
+		blk_mq_tag_set_rq(hctx, flush_rq->tag, fq->orig_rq);
 		flush_rq->tag = -1;
 	}
 
@@ -308,11 +314,18 @@
 
 	/*
 	 * Borrow tag from the first request since they can't
-	 * be in flight at the same time.
+	 * be in flight at the same time. And acquire the tag's
+	 * ownership for flush req.
 	 */
 	if (q->mq_ops) {
+		struct blk_mq_hw_ctx *hctx;
+
 		flush_rq->mq_ctx = first_rq->mq_ctx;
 		flush_rq->tag = first_rq->tag;
+		fq->orig_rq = first_rq;
+
+		hctx = q->mq_ops->map_queue(q, first_rq->mq_ctx->cpu);
+		blk_mq_tag_set_rq(hctx, first_rq->tag, flush_rq);
 	}
 
 	flush_rq->cmd_type = REQ_TYPE_FS;
```
