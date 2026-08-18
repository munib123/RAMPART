# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1864_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1864_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 6759-6799 of the vulnerable file.

			goto free_idr;
	}

skip_type:
	pmu->pmu_cpu_context = find_pmu_context(pmu->task_ctx_nr);
	if (pmu->pmu_cpu_context)
		goto got_cpu_context;

	ret = -ENOMEM;
	pmu->pmu_cpu_context = alloc_percpu(struct perf_cpu_context);
	if (!pmu->pmu_cpu_context)
		goto free_dev;

	for_each_possible_cpu(cpu) {
		struct perf_cpu_context *cpuctx;

		cpuctx = per_cpu_ptr(pmu->pmu_cpu_context, cpu);
		__perf_event_init_context(&cpuctx->ctx);
		lockdep_set_class(&cpuctx->ctx.mutex, &cpuctx_mutex);
		lockdep_set_class(&cpuctx->ctx.lock, &cpuctx_lock);
		cpuctx->ctx.type = cpu_context;
		cpuctx->ctx.pmu = pmu;

		__perf_cpu_hrtimer_init(cpuctx, cpu);

		INIT_LIST_HEAD(&cpuctx->rotation_list);
		cpuctx->unique_pmu = pmu;
	}

got_cpu_context:
	if (!pmu->start_txn) {
		if (pmu->pmu_enable) {
			/*
			 * If we have pmu_enable/pmu_disable calls, install
			 * transaction stubs that use that to try and batch
			 * hardware accesses.
			 */
			pmu->start_txn  = perf_pmu_start_txn;
			pmu->commit_txn = perf_pmu_commit_txn;
			pmu->cancel_txn = perf_pmu_cancel_txn;
		} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6776,7 +6776,6 @@
 		__perf_event_init_context(&cpuctx->ctx);
 		lockdep_set_class(&cpuctx->ctx.mutex, &cpuctx_mutex);
 		lockdep_set_class(&cpuctx->ctx.lock, &cpuctx_lock);
-		cpuctx->ctx.type = cpu_context;
 		cpuctx->ctx.pmu = pmu;
 
 		__perf_cpu_hrtimer_init(cpuctx, cpu);
@@ -7420,7 +7419,19 @@
 		 * task or CPU context:
 		 */
 		if (move_group) {
-			if (group_leader->ctx->type != ctx->type)
+			/*
+			 * Make sure we're both on the same task, or both
+			 * per-cpu events.
+			 */
+			if (group_leader->ctx->task != ctx->task)
+				goto err_context;
+
+			/*
+			 * Make sure we're both events for the same CPU;
+			 * grouping events for different CPUs is broken; since
+			 * you can never concurrently schedule them anyhow.
+			 */
+			if (group_leader->cpu != event->cpu)
 				goto err_context;
 		} else {
 			if (group_leader->ctx != ctx)
```
