# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2840_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2840_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 571-611 of the vulnerable file.

					      struct userfaultfd_wait_queue *ewq)
{
	if (WARN_ON_ONCE(current->flags & PF_EXITING))
		goto out;

	ewq->ctx = ctx;
	init_waitqueue_entry(&ewq->wq, current);

	spin_lock(&ctx->event_wqh.lock);
	/*
	 * After the __add_wait_queue the uwq is visible to userland
	 * through poll/read().
	 */
	__add_wait_queue(&ctx->event_wqh, &ewq->wq);
	for (;;) {
		set_current_state(TASK_KILLABLE);
		if (ewq->msg.event == 0)
			break;
		if (ACCESS_ONCE(ctx->released) ||
		    fatal_signal_pending(current)) {
			__remove_wait_queue(&ctx->event_wqh, &ewq->wq);
			if (ewq->msg.event == UFFD_EVENT_FORK) {
				struct userfaultfd_ctx *new;

				new = (struct userfaultfd_ctx *)
					(unsigned long)
					ewq->msg.arg.reserved.reserved1;

				userfaultfd_ctx_put(new);
			}
			break;
		}

		spin_unlock(&ctx->event_wqh.lock);

		wake_up_poll(&ctx->fd_wqh, POLLIN);
		schedule();

		spin_lock(&ctx->event_wqh.lock);
	}
	__set_current_state(TASK_RUNNING);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -588,6 +588,12 @@
 			break;
 		if (ACCESS_ONCE(ctx->released) ||
 		    fatal_signal_pending(current)) {
+			/*
+			 * &ewq->wq may be queued in fork_event, but
+			 * __remove_wait_queue ignores the head
+			 * parameter. It would be a problem if it
+			 * didn't.
+			 */
 			__remove_wait_queue(&ctx->event_wqh, &ewq->wq);
 			if (ewq->msg.event == UFFD_EVENT_FORK) {
 				struct userfaultfd_ctx *new;
@@ -1061,6 +1067,12 @@
 					(unsigned long)
 					uwq->msg.arg.reserved.reserved1;
 				list_move(&uwq->wq.entry, &fork_event);
+				/*
+				 * fork_nctx can be freed as soon as
+				 * we drop the lock, unless we take a
+				 * reference on it.
+				 */
+				userfaultfd_ctx_get(fork_nctx);
 				spin_unlock(&ctx->event_wqh.lock);
 				ret = 0;
 				break;
@@ -1091,19 +1103,53 @@
 
 	if (!ret && msg->event == UFFD_EVENT_FORK) {
 		ret = resolve_userfault_fork(ctx, fork_nctx, msg);
-
-		if (!ret) {
-			spin_lock(&ctx->event_wqh.lock);
-			if (!list_empty(&fork_event)) {
-				uwq = list_first_entry(&fork_event,
-						       typeof(*uwq),
-						       wq.entry);
-				list_del(&uwq->wq.entry);
-				__add_wait_queue(&ctx->event_wqh, &uwq->wq);
+		spin_lock(&ctx->event_wqh.lock);
+		if (!list_empty(&fork_event)) {
+			/*
+			 * The fork thread didn't abort, so we can
+			 * drop the temporary refcount.
+			 */
+			userfaultfd_ctx_put(fork_nctx);
+
+			uwq = list_first_entry(&fork_event,
+					       typeof(*uwq),
+					       wq.entry);
+			/*
+			 * If fork_event list wasn't empty and in turn
+			 * the event wasn't already released by fork
+			 * (the event is allocated on fork kernel
+			 * stack), put the event back to its place in
+			 * the event_wq. fork_event head will be freed
+			 * as soon as we return so the event cannot
+			 * stay queued there no matter the current
+			 * "ret" value.
+			 */
+			list_del(&uwq->wq.entry);
+			__add_wait_queue(&ctx->event_wqh, &uwq->wq);
+
+			/*
+			 * Leave the event in the waitqueue and report
+			 * error to userland if we failed to resolve
+			 * the userfault fork.
+			 */
+			if (likely(!ret))
 				userfaultfd_event_complete(ctx, uwq);
-			}
-			spin_unlock(&ctx->event_wqh.lock);
+		} else {
+			/*
+			 * Here the fork thread aborted and the
+			 * refcount from the fork thread on fork_nctx
+			 * has already been released. We still hold
+			 * the reference we took before releasing the
+			 * lock above. If resolve_userfault_fork
+			 * failed we've to drop it because the
+			 * fork_nctx has to be freed in such case. If
+			 * it succeeded we'll hold it because the new
+			 * uffd references it.
+			 */
+			if (ret)
+				userfaultfd_ctx_put(fork_nctx);
 		}
+		spin_unlock(&ctx->event_wqh.lock);
 	}
 
 	return ret;
```
