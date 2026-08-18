# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2550_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2550_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 23-63 of the vulnerable file.

#include <linux/anon_inodes.h>
#include <linux/timerfd.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/rcupdate.h>

struct timerfd_ctx {
	union {
		struct hrtimer tmr;
		struct alarm alarm;
	} t;
	ktime_t tintv;
	ktime_t moffs;
	wait_queue_head_t wqh;
	u64 ticks;
	int clockid;
	short unsigned expired;
	short unsigned settime_flags;	/* to show in fdinfo */
	struct rcu_head rcu;
	struct list_head clist;
	bool might_cancel;
};

static LIST_HEAD(cancel_list);
static DEFINE_SPINLOCK(cancel_lock);

static inline bool isalarm(struct timerfd_ctx *ctx)
{
	return ctx->clockid == CLOCK_REALTIME_ALARM ||
		ctx->clockid == CLOCK_BOOTTIME_ALARM;
}

/*
 * This gets called when the timer event triggers. We set the "expired"
 * flag, but we do not re-arm the timer (in case it's necessary,
 * tintv != 0) until the timer is accessed.
 */
static void timerfd_triggered(struct timerfd_ctx *ctx)
{
	unsigned long flags;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,7 @@
 	short unsigned settime_flags;	/* to show in fdinfo */
 	struct rcu_head rcu;
 	struct list_head clist;
+	spinlock_t cancel_lock;
 	bool might_cancel;
 };
 
@@ -112,7 +113,7 @@
 	rcu_read_unlock();
 }
 
-static void timerfd_remove_cancel(struct timerfd_ctx *ctx)
+static void __timerfd_remove_cancel(struct timerfd_ctx *ctx)
 {
 	if (ctx->might_cancel) {
 		ctx->might_cancel = false;
@@ -122,6 +123,13 @@
 	}
 }
 
+static void timerfd_remove_cancel(struct timerfd_ctx *ctx)
+{
+	spin_lock(&ctx->cancel_lock);
+	__timerfd_remove_cancel(ctx);
+	spin_unlock(&ctx->cancel_lock);
+}
+
 static bool timerfd_canceled(struct timerfd_ctx *ctx)
 {
 	if (!ctx->might_cancel || ctx->moffs != KTIME_MAX)
@@ -132,6 +140,7 @@
 
 static void timerfd_setup_cancel(struct timerfd_ctx *ctx, int flags)
 {
+	spin_lock(&ctx->cancel_lock);
 	if ((ctx->clockid == CLOCK_REALTIME ||
 	     ctx->clockid == CLOCK_REALTIME_ALARM) &&
 	    (flags & TFD_TIMER_ABSTIME) && (flags & TFD_TIMER_CANCEL_ON_SET)) {
@@ -141,9 +150,10 @@
 			list_add_rcu(&ctx->clist, &cancel_list);
 			spin_unlock(&cancel_lock);
 		}
-	} else if (ctx->might_cancel) {
-		timerfd_remove_cancel(ctx);
-	}
+	} else {
+		__timerfd_remove_cancel(ctx);
+	}
+	spin_unlock(&ctx->cancel_lock);
 }
 
 static ktime_t timerfd_get_remaining(struct timerfd_ctx *ctx)
@@ -400,6 +410,7 @@
 		return -ENOMEM;
 
 	init_waitqueue_head(&ctx->wqh);
+	spin_lock_init(&ctx->cancel_lock);
 	ctx->clockid = clockid;
 
 	if (isalarm(ctx))
```
