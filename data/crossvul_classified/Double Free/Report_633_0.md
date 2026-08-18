# CrossVul Fix Pair: Double Free in c
**Pair ID:** 633_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `633_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 1062-1103 of the vulnerable file.

	new_blkg = blkg_alloc(&blkcg_root, q, GFP_KERNEL);
	if (!new_blkg)
		return -ENOMEM;

	preloaded = !radix_tree_preload(GFP_KERNEL);

	/*
	 * Make sure the root blkg exists and count the existing blkgs.  As
	 * @q is bypassing at this point, blkg_lookup_create() can't be
	 * used.  Open code insertion.
	 */
	rcu_read_lock();
	spin_lock_irq(q->queue_lock);
	blkg = blkg_create(&blkcg_root, q, new_blkg);
	spin_unlock_irq(q->queue_lock);
	rcu_read_unlock();

	if (preloaded)
		radix_tree_preload_end();

	if (IS_ERR(blkg)) {
		blkg_free(new_blkg);
		return PTR_ERR(blkg);
	}

	q->root_blkg = blkg;
	q->root_rl.blkg = blkg;

	ret = blk_throtl_init(q);
	if (ret) {
		spin_lock_irq(q->queue_lock);
		blkg_destroy_all(q);
		spin_unlock_irq(q->queue_lock);
	}
	return ret;
}

/**
 * blkcg_drain_queue - drain blkcg part of request_queue
 * @q: request_queue to drain
 *
 * Called from blk_drain_queue().  Responsible for draining blkcg part.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1079,10 +1079,8 @@
 	if (preloaded)
 		radix_tree_preload_end();
 
-	if (IS_ERR(blkg)) {
-		blkg_free(new_blkg);
+	if (IS_ERR(blkg))
 		return PTR_ERR(blkg);
-	}
 
 	q->root_blkg = blkg;
 	q->root_rl.blkg = blkg;
```
