# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3159_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3159_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 9512-9552 of the vulnerable file.

		break;

	case CLOCK_BOOTTIME:
		event->clock = &ktime_get_boot_ns;
		break;

	case CLOCK_TAI:
		event->clock = &ktime_get_tai_ns;
		break;

	default:
		return -EINVAL;
	}

	if (!nmi_safe && !(event->pmu->capabilities & PERF_PMU_CAP_NO_NMI))
		return -EINVAL;

	return 0;
}

/**
 * sys_perf_event_open - open a performance event, associate it to a task/cpu
 *
 * @attr_uptr:	event_id type attributes for monitoring/sampling
 * @pid:		target pid
 * @cpu:		target cpu
 * @group_fd:		group leader event fd
 */
SYSCALL_DEFINE5(perf_event_open,
		struct perf_event_attr __user *, attr_uptr,
		pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
{
	struct perf_event *group_leader = NULL, *output_event = NULL;
	struct perf_event *event, *sibling;
	struct perf_event_attr attr;
	struct perf_event_context *ctx, *uninitialized_var(gctx);
	struct file *event_file = NULL;
	struct fd group = {NULL, 0};
	struct task_struct *task = NULL;
	struct pmu *pmu;
	int event_fd;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9529,6 +9529,37 @@
 	return 0;
 }
 
+/*
+ * Variation on perf_event_ctx_lock_nested(), except we take two context
+ * mutexes.
+ */
+static struct perf_event_context *
+__perf_event_ctx_lock_double(struct perf_event *group_leader,
+			     struct perf_event_context *ctx)
+{
+	struct perf_event_context *gctx;
+
+again:
+	rcu_read_lock();
+	gctx = READ_ONCE(group_leader->ctx);
+	if (!atomic_inc_not_zero(&gctx->refcount)) {
+		rcu_read_unlock();
+		goto again;
+	}
+	rcu_read_unlock();
+
+	mutex_lock_double(&gctx->mutex, &ctx->mutex);
+
+	if (group_leader->ctx != gctx) {
+		mutex_unlock(&ctx->mutex);
+		mutex_unlock(&gctx->mutex);
+		put_ctx(gctx);
+		goto again;
+	}
+
+	return gctx;
+}
+
 /**
  * sys_perf_event_open - open a performance event, associate it to a task/cpu
  *
@@ -9772,11 +9803,30 @@
 	}
 
 	if (move_group) {
-		gctx = group_leader->ctx;
-		mutex_lock_double(&gctx->mutex, &ctx->mutex);
+		gctx = __perf_event_ctx_lock_double(group_leader, ctx);
+
 		if (gctx->task == TASK_TOMBSTONE) {
 			err = -ESRCH;
 			goto err_locked;
+		}
+
+		/*
+		 * Check if we raced against another sys_perf_event_open() call
+		 * moving the software group underneath us.
+		 */
+		if (!(group_leader->group_caps & PERF_EV_CAP_SOFTWARE)) {
+			/*
+			 * If someone moved the group out from under us, check
+			 * if this new event wound up on the same ctx, if so
+			 * its the regular !move_group case, otherwise fail.
+			 */
+			if (gctx != ctx) {
+				err = -EINVAL;
+				goto err_locked;
+			} else {
+				perf_event_ctx_unlock(group_leader, gctx);
+				move_group = 0;
+			}
 		}
 	} else {
 		mutex_lock(&ctx->mutex);
@@ -9879,7 +9929,7 @@
 	perf_unpin_context(ctx);
 
 	if (move_group)
-		mutex_unlock(&gctx->mutex);
+		perf_event_ctx_unlock(group_leader, gctx);
 	mutex_unlock(&ctx->mutex);
 
 	if (task) {
@@ -9905,7 +9955,7 @@
 
 err_locked:
 	if (move_group)
-		mutex_unlock(&gctx->mutex);
+		perf_event_ctx_unlock(group_leader, gctx);
 	mutex_unlock(&ctx->mutex);
 /* err_file: */
 	fput(event_file);
```
