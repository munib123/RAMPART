# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 527_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `527_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/*
 * Completely Fair Scheduling (CFS) Class (SCHED_NORMAL/SCHED_BATCH)
 *
 *  Copyright (C) 2007 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 *  Interactivity improvements by Mike Galbraith
 *  (C) 2007 Mike Galbraith <efault@gmx.de>
 *
 *  Various enhancements by Dmitry Adamushko.
 *  (C) 2007 Dmitry Adamushko <dmitry.adamushko@gmail.com>
 *
 *  Group scheduling enhancements by Srivatsa Vaddagiri
 *  Copyright IBM Corporation, 2007
 *  Author: Srivatsa Vaddagiri <vatsa@linux.vnet.ibm.com>
 *
 *  Scaled math optimizations by Thomas Gleixner
 *  Copyright (C) 2007, Thomas Gleixner <tglx@linutronix.de>
 *
 *  Adaptive scheduling granularity, math enhancements by Peter Zijlstra
 *  Copyright (C) 2007 Red Hat, Inc., Peter Zijlstra
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
+// SPDX-License-Identifier: GPL-2.0
 /*
  * Completely Fair Scheduling (CFS) Class (SCHED_NORMAL/SCHED_BATCH)
  *
@@ -19,23 +20,9 @@
  *  Adaptive scheduling granularity, math enhancements by Peter Zijlstra
  *  Copyright (C) 2007 Red Hat, Inc., Peter Zijlstra
  */
-
-#include <linux/sched/mm.h>
-#include <linux/sched/topology.h>
-
-#include <linux/latencytop.h>
-#include <linux/cpumask.h>
-#include <linux/cpuidle.h>
-#include <linux/slab.h>
-#include <linux/profile.h>
-#include <linux/interrupt.h>
-#include <linux/mempolicy.h>
-#include <linux/migrate.h>
-#include <linux/task_work.h>
+#include "sched.h"
 
 #include <trace/events/sched.h>
-
-#include "sched.h"
 
 /*
  * Targeted preemption latency for CPU-bound tasks:
@@ -51,7 +38,7 @@
  * (default: 6ms * (1 + ilog(ncpus)), units: nanoseconds)
  */
 unsigned int sysctl_sched_latency			= 6000000ULL;
-unsigned int normalized_sysctl_sched_latency		= 6000000ULL;
+static unsigned int normalized_sysctl_sched_latency	= 6000000ULL;
 
 /*
  * The initial- and re-scaling of tunables is configurable
@@ -71,8 +58,8 @@
  *
  * (default: 0.75 msec * (1 + ilog(ncpus)), units: nanoseconds)
  */
-unsigned int sysctl_sched_min_granularity		= 750000ULL;
-unsigned int normalized_sysctl_sched_min_granularity	= 750000ULL;
+unsigned int sysctl_sched_min_granularity			= 750000ULL;
+static unsigned int normalized_sysctl_sched_min_granularity	= 750000ULL;
 
 /*
  * This value is kept at sysctl_sched_latency/sysctl_sched_min_granularity
@@ -94,19 +81,27 @@
  *
  * (default: 1 msec * (1 + ilog(ncpus)), units: nanoseconds)
  */
-unsigned int sysctl_sched_wakeup_granularity		= 1000000UL;
-unsigned int normalized_sysctl_sched_wakeup_granularity	= 1000000UL;
+unsigned int sysctl_sched_wakeup_granularity			= 1000000UL;
+static unsigned int normalized_sysctl_sched_wakeup_granularity	= 1000000UL;
 
 const_debug unsigned int sysctl_sched_migration_cost	= 500000UL;
 
 #ifdef CONFIG_SMP
 /*
- * For asym packing, by default the lower numbered cpu has higher priority.
+ * For asym packing, by default the lower numbered CPU has higher priority.
  */
 int __weak arch_asym_cpu_priority(int cpu)
 {
 	return -cpu;
 }
+
+/*
+ * The margin used when comparing utilization with CPU capacity:
+ * util * margin < capacity * 1024
+ *
+ * (default: ~20%)
+ */
+static unsigned int capacity_margin			= 1280;
 #endif
 
 #ifdef CONFIG_CFS_BANDWIDTH
@@ -122,14 +117,6 @@
  */
 unsigned int sysctl_sched_cfs_bandwidth_slice		= 5000UL;
 #endif
-
-/*
- * The margin used when comparing utilization with CPU capacity:
- * util * margin < capacity * 1024
- *
- * (default: ~20%)
- */
-unsigned int capacity_margin				= 1280;
 
 static inline void update_load_add(struct load_weight *lw, unsigned long inc)
 {
@@ -267,9 +254,6 @@
 {
 	return cfs_rq->rq;
 }
-
-/* An entity is a task if it doesn't "own" a runqueue */
-#define entity_is_task(se)	(!se->my_q)
 
 static inline struct task_struct *task_of(struct sched_entity *se)
 {
@@ -368,10 +352,9 @@
 	}
 }
 
-/* Iterate thr' all leaf cfs_rq's on a runqueue */
-#define for_each_leaf_cfs_rq_safe(rq, cfs_rq, pos)			\
-	list_for_each_entry_safe(cfs_rq, pos, &rq->leaf_cfs_rq_list,	\
-				 leaf_cfs_rq_list)
+/* Iterate through all leaf cfs_rq's on a runqueue: */
+#define for_each_leaf_cfs_rq(rq, cfs_rq) \
+	list_for_each_entry_rcu(cfs_rq, &rq->leaf_cfs_rq_list, leaf_cfs_rq_list)
 
 /* Do the two (enqueued) entities belong to the same group ? */
 static inline struct cfs_rq *
@@ -432,7 +415,6 @@
 	return container_of(cfs_rq, struct rq, cfs);
 }
 
-#define entity_is_task(se)	1
 
 #define for_each_sched_entity(se) \
 		for (; se; se = NULL)
@@ -464,8 +446,8 @@
 {
 }
 
-#define for_each_leaf_cfs_rq_safe(rq, cfs_rq, pos)	\
-		for (cfs_rq = &rq->cfs, pos = NULL; cfs_rq; cfs_rq = pos)
+#define for_each_leaf_cfs_rq(rq, cfs_rq)	\
+		for (cfs_rq = &rq->cfs; cfs_rq; cfs_rq = NULL)
 
 static inline struct sched_entity *parent_entity(struct sched_entity *se)
 {
@@ -513,6 +495,7 @@
 static void update_min_vruntime(struct cfs_rq *cfs_rq)
 {
 	struct sched_entity *curr = cfs_rq->curr;
+	struct rb_node *leftmost = rb_first_cached(&cfs_rq->tasks_timeline);
 
 	u64 vruntime = cfs_rq->min_vruntime;
 
@@ -523,10 +506,9 @@
 			curr = NULL;
 	}
 
-	if (cfs_rq->rb_leftmost) {
-		struct sched_entity *se = rb_entry(cfs_rq->rb_leftmost,
-						   struct sched_entity,
-						   run_node);
+	if (leftmost) { /* non-empty tree */
+		struct sched_entity *se;
+		se = rb_entry(leftmost, struct sched_entity, run_node);
 
 		if (!curr)
 			vruntime = se->vruntime;
@@ -547,10 +529,10 @@
  */
 static void __enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
 {
-	struct rb_node **link = &cfs_rq->tasks_timeline.rb_node;
+	struct rb_node **link = &cfs_rq->tasks_timeline.rb_root.rb_node;
 	struct rb_node *parent = NULL;
 	struct sched_entity *entry;
-	int leftmost = 1;
+	bool leftmost = true;
 
 	/*
 	 * Find the right place in the rbtree:
@@ -566,36 +548,23 @@
 			link = &parent->rb_left;
 		} else {
 			link = &parent->rb_right;
-			leftmost = 0;
+			leftmost = false;
 		}
 	}
 
-	/*
-	 * Maintain a cache of leftmost tree entries (it is frequently
-	 * used):
-	 */
-	if (leftmost)
-		cfs_rq->rb_leftmost = &se->run_node;
-
 	rb_link_node(&se->run_node, parent, link);
-	rb_insert_color(&se->run_node, &cfs_rq->tasks_timeline);
+	rb_insert_color_cached(&se->run_node,
+			       &cfs_rq->tasks_timeline, leftmost);
 }
 
 static void __dequeue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
 {
-	if (cfs_rq->rb_leftmost == &se->run_node) {
-		struct rb_node *next_node;
-
-		next_node = rb_next(&se->run_node);
-		cfs_rq->rb_leftmost = next_node;
-	}
-
-	rb_erase(&se->run_node, &cfs_rq->tasks_timeline);
+	rb_erase_cached(&se->run_node, &cfs_rq->tasks_timeline);
 }
 
 struct sched_entity *__pick_first_entity(struct cfs_rq *cfs_rq)
 {
-	struct rb_node *left = cfs_rq->rb_leftmost;
+	struct rb_node *left = rb_first_cached(&cfs_rq->tasks_timeline);
 
 	if (!left)
 		return NULL;
@@ -616,7 +585,7 @@
 #ifdef CONFIG_SCHED_DEBUG
 struct sched_entity *__pick_last_entity(struct cfs_rq *cfs_rq)
 {
-	struct rb_node *last = rb_last(&cfs_rq->tasks_timeline);
+	struct rb_node *last = rb_last(&cfs_rq->tasks_timeline.rb_root);
 
 	if (!last)
 		return NULL;
@@ -718,38 +687,31 @@
 }
 
 #ifdef CONFIG_SMP
-
+#include "pelt.h"
 #include "sched-pelt.h"
 
 static int select_idle_sibling(struct task_struct *p, int prev_cpu, int cpu);
 static unsigned long task_h_load(struct task_struct *p);
+static unsigned long capacity_of(int cpu);
 
 /* Give new sched_entity start runnable values to heavy its load in infant time */
 void init_entity_runnable_average(struct sched_entity *se)
 {
 	struct sched_avg *sa = &se->avg;
 
-	sa->last_update_time = 0;
-	/*
-	 * sched_avg's period_contrib should be strictly less then 1024, so
-	 * we give it 1023 to make sure it is almost a period (1024us), and
-	 * will definitely be update (after enqueue).
-	 */
-	sa->period_contrib = 1023;
-	/*
-	 * Tasks are intialized with full load to be seen as heavy tasks until
+	memset(sa, 0, sizeof(*sa));
+
+	/*
+	 * Tasks are initialized with full load to be seen as heavy tasks until
 	 * they get a chance to stabilize to their real load level.
-	 * Group entities are intialized with zero load to reflect the fact that
+	 * Group entities are initialized with zero load to reflect the fact that
 	 * nothing has been attached to the task group yet.
 	 */
 	if (entity_is_task(se))
-		sa->load_avg = scale_load_down(se->load.weight);
-	sa->load_sum = sa->load_avg * LOAD_AVG_MAX;
-	/*
-	 * At this point, util_avg won't be used in select_task_rq_fair anyway
-	 */
-	sa->util_avg = 0;
-	sa->util_sum = 0;
+		sa->runnable_load_avg = sa->load_avg = scale_load_down(se->load.weight);
+
+	se->runnable_weight = se->load.weight;
+
 	/* when this task enqueue'ed, it will contribute to its cfs_rq's load_avg */
 }
 
@@ -769,11 +731,12 @@
... (diff truncated)
```
