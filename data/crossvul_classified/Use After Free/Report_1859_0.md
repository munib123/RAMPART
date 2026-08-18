# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1859_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1859_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 6471-6513 of the vulnerable file.

}

int perf_event_overflow(struct perf_event *event,
			  struct perf_sample_data *data,
			  struct pt_regs *regs)
{
	return __perf_event_overflow(event, 1, data, regs);
}

/*
 * Generic software event infrastructure
 */

struct swevent_htable {
	struct swevent_hlist		*swevent_hlist;
	struct mutex			hlist_mutex;
	int				hlist_refcount;

	/* Recursion avoidance in each contexts */
	int				recursion[PERF_NR_CONTEXTS];

	/* Keeps track of cpu being initialized/exited */
	bool				online;
};

static DEFINE_PER_CPU(struct swevent_htable, swevent_htable);

/*
 * We directly increment event->count and keep a second value in
 * event->hw.period_left to count intervals. This period event
 * is kept in the range [-sample_period, 0] so that we can use the
 * sign as trigger.
 */

u64 perf_swevent_set_period(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 period = hwc->last_period;
	u64 nr, offset;
	s64 old, val;

	hwc->last_period = hwc->sample_period;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6488,9 +6488,6 @@
 
 	/* Recursion avoidance in each contexts */
 	int				recursion[PERF_NR_CONTEXTS];
-
-	/* Keeps track of cpu being initialized/exited */
-	bool				online;
 };
 
 static DEFINE_PER_CPU(struct swevent_htable, swevent_htable);
@@ -6748,14 +6745,8 @@
 	hwc->state = !(flags & PERF_EF_START);
 
 	head = find_swevent_head(swhash, event);
-	if (!head) {
-		/*
-		 * We can race with cpu hotplug code. Do not
-		 * WARN if the cpu just got unplugged.
-		 */
-		WARN_ON_ONCE(swhash->online);
+	if (WARN_ON_ONCE(!head))
 		return -EINVAL;
-	}
 
 	hlist_add_head_rcu(&event->hlist_entry, head);
 	perf_event_update_userpage(event);
@@ -6823,7 +6814,6 @@
 	int err = 0;
 
 	mutex_lock(&swhash->hlist_mutex);
-
 	if (!swevent_hlist_deref(swhash) && cpu_online(cpu)) {
 		struct swevent_hlist *hlist;
 
@@ -9286,7 +9276,6 @@
 	struct swevent_htable *swhash = &per_cpu(swevent_htable, cpu);
 
 	mutex_lock(&swhash->hlist_mutex);
-	swhash->online = true;
 	if (swhash->hlist_refcount > 0) {
 		struct swevent_hlist *hlist;
 
@@ -9328,14 +9317,7 @@
 
 static void perf_event_exit_cpu(int cpu)
 {
-	struct swevent_htable *swhash = &per_cpu(swevent_htable, cpu);
-
 	perf_event_exit_cpu_context(cpu);
-
-	mutex_lock(&swhash->hlist_mutex);
-	swhash->online = false;
-	swevent_hlist_release(swhash);
-	mutex_unlock(&swhash->hlist_mutex);
 }
 #else
 static inline void perf_event_exit_cpu(int cpu) { }
```
