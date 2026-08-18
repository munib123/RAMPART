# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3573_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3573_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 459-499 of the vulnerable file.


	return req;
}

/*
 * struct kiocb's are allocated in batches to reduce the number of
 * times the ctx lock is acquired and released.
 */
#define KIOCB_BATCH_SIZE	32L
struct kiocb_batch {
	struct list_head head;
	long count; /* number of requests left to allocate */
};

static void kiocb_batch_init(struct kiocb_batch *batch, long total)
{
	INIT_LIST_HEAD(&batch->head);
	batch->count = total;
}

static void kiocb_batch_free(struct kiocb_batch *batch)
{
	struct kiocb *req, *n;

	list_for_each_entry_safe(req, n, &batch->head, ki_batch) {
		list_del(&req->ki_batch);
		kmem_cache_free(kiocb_cachep, req);
	}
}

/*
 * Allocate a batch of kiocbs.  This avoids taking and dropping the
 * context lock a lot during setup.
 */
static int kiocb_batch_refill(struct kioctx *ctx, struct kiocb_batch *batch)
{
	unsigned short allocated, to_alloc;
	long avail;
	bool called_fput = false;
	struct kiocb *req, *n;
	struct aio_ring *ring;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -476,14 +476,21 @@
 	batch->count = total;
 }
 
-static void kiocb_batch_free(struct kiocb_batch *batch)
+static void kiocb_batch_free(struct kioctx *ctx, struct kiocb_batch *batch)
 {
 	struct kiocb *req, *n;
 
+	if (list_empty(&batch->head))
+		return;
+
+	spin_lock_irq(&ctx->ctx_lock);
 	list_for_each_entry_safe(req, n, &batch->head, ki_batch) {
 		list_del(&req->ki_batch);
+		list_del(&req->ki_list);
 		kmem_cache_free(kiocb_cachep, req);
-	}
+		ctx->reqs_active--;
+	}
+	spin_unlock_irq(&ctx->ctx_lock);
 }
 
 /*
@@ -1742,7 +1749,7 @@
 	}
 	blk_finish_plug(&plug);
 
-	kiocb_batch_free(&batch);
+	kiocb_batch_free(ctx, &batch);
 	put_ioctx(ctx);
 	return i ? i : ret;
 }
```
