# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5856_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5856_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 593-633 of the vulnerable file.

		spin_unlock(&aio_nr_lock);
		err = -EAGAIN;
		goto err;
	}
	aio_nr += ctx->max_reqs;
	spin_unlock(&aio_nr_lock);

	percpu_ref_get(&ctx->users); /* io_setup() will drop this ref */

	err = ioctx_add_table(ctx, mm);
	if (err)
		goto err_cleanup;

	pr_debug("allocated ioctx %p[%ld]: mm=%p mask=0x%x\n",
		 ctx, ctx->user_id, mm, ctx->nr_events);
	return ctx;

err_cleanup:
	aio_nr_sub(ctx->max_reqs);
err:
	aio_free_ring(ctx);
	free_percpu(ctx->cpu);
	free_percpu(ctx->reqs.pcpu_count);
	free_percpu(ctx->users.pcpu_count);
	kmem_cache_free(kioctx_cachep, ctx);
	pr_debug("error allocating ioctx %d\n", err);
	return ERR_PTR(err);
}

/* kill_ioctx
 *	Cancels all outstanding aio requests on an aio context.  Used
 *	when the processes owning a context have all exited to encourage
 *	the rapid destruction of the kioctx.
 */
static void kill_ioctx(struct mm_struct *mm, struct kioctx *ctx)
{
	if (!atomic_xchg(&ctx->dead, 1)) {
		struct kioctx_table *table;

		spin_lock(&mm->ioctx_lock);
		rcu_read_lock();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -610,7 +610,6 @@
 err_cleanup:
 	aio_nr_sub(ctx->max_reqs);
 err:
-	aio_free_ring(ctx);
 	free_percpu(ctx->cpu);
 	free_percpu(ctx->reqs.pcpu_count);
 	free_percpu(ctx->users.pcpu_count);
```
