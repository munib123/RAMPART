# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3580_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3580_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 63-103 of the vulnerable file.

		cic->exit(ioc);
	}
	rcu_read_unlock();
}

/* Called by the exitting task */
void exit_io_context(void)
{
	struct io_context *ioc;

	task_lock(current);
	ioc = current->io_context;
	current->io_context = NULL;
	task_unlock(current);

	if (atomic_dec_and_test(&ioc->nr_tasks)) {
		if (ioc->aic && ioc->aic->exit)
			ioc->aic->exit(ioc->aic);
		cfq_exit(ioc);

		put_io_context(ioc);
	}
}

struct io_context *alloc_io_context(gfp_t gfp_flags, int node)
{
	struct io_context *ret;

	ret = kmem_cache_alloc_node(iocontext_cachep, gfp_flags, node);
	if (ret) {
		atomic_long_set(&ret->refcount, 1);
		atomic_set(&ret->nr_tasks, 1);
		spin_lock_init(&ret->lock);
		ret->ioprio_changed = 0;
		ret->ioprio = 0;
		ret->last_waited = jiffies; /* doesn't matter... */
		ret->nr_batch_requests = 0; /* because this is 0 */
		ret->aic = NULL;
		INIT_RADIX_TREE(&ret->radix_root, GFP_ATOMIC | __GFP_HIGH);
		INIT_HLIST_HEAD(&ret->cic_list);
		ret->ioc_data = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,8 +80,8 @@
 			ioc->aic->exit(ioc->aic);
 		cfq_exit(ioc);
 
-		put_io_context(ioc);
 	}
+	put_io_context(ioc);
 }
 
 struct io_context *alloc_io_context(gfp_t gfp_flags, int node)
```
