# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4007_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4007_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/*
 * Budget Fair Queueing (BFQ) I/O scheduler.
 *
 * Based on ideas and code from CFQ:
 * Copyright (C) 2003 Jens Axboe <axboe@kernel.dk>
 *
 * Copyright (C) 2008 Fabio Checconi <fabio@gandalf.sssup.it>
 *		      Paolo Valente <paolo.valente@unimore.it>
 *
 * Copyright (C) 2010 Paolo Valente <paolo.valente@unimore.it>
 *                    Arianna Avanzini <avanzini@google.com>
 *
 * Copyright (C) 2017 Paolo Valente <paolo.valente@linaro.org>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
 /*
  * Budget Fair Queueing (BFQ) I/O scheduler.
  *
@@ -11,22 +12,12 @@
  *                    Arianna Avanzini <avanzini@google.com>
  *
  * Copyright (C) 2017 Paolo Valente <paolo.valente@linaro.org>
- *
- *  This program is free software; you can redistribute it and/or
- *  modify it under the terms of the GNU General Public License as
- *  published by the Free Software Foundation; either version 2 of the
- *  License, or (at your option) any later version.
- *
- *  This program is distributed in the hope that it will be useful,
- *  but WITHOUT ANY WARRANTY; without even the implied warranty of
- *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
- *  General Public License for more details.
  *
  * BFQ is a proportional-share I/O scheduler, with some extra
  * low-latency capabilities. BFQ also supports full hierarchical
  * scheduling through cgroups. Next paragraphs provide an introduction
  * on BFQ inner workings. Details on BFQ benefits, usage and
- * limitations can be found in Documentation/block/bfq-iosched.txt.
+ * limitations can be found in Documentation/block/bfq-iosched.rst.
  *
  * BFQ is a proportional-share storage-I/O scheduling algorithm based
  * on the slice-by-slice service scheme of CFQ. But BFQ assigns
@@ -49,21 +40,56 @@
  *
  * In particular, to provide these low-latency guarantees, BFQ
  * explicitly privileges the I/O of two classes of time-sensitive
- * applications: interactive and soft real-time. This feature enables
- * BFQ to provide applications in these classes with a very low
- * latency. Finally, BFQ also features additional heuristics for
+ * applications: interactive and soft real-time. In more detail, BFQ
+ * behaves this way if the low_latency parameter is set (default
+ * configuration). This feature enables BFQ to provide applications in
+ * these classes with a very low latency.
+ *
+ * To implement this feature, BFQ constantly tries to detect whether
+ * the I/O requests in a bfq_queue come from an interactive or a soft
+ * real-time application. For brevity, in these cases, the queue is
+ * said to be interactive or soft real-time. In both cases, BFQ
+ * privileges the service of the queue, over that of non-interactive
+ * and non-soft-real-time queues. This privileging is performed,
+ * mainly, by raising the weight of the queue. So, for brevity, we
+ * call just weight-raising periods the time periods during which a
+ * queue is privileged, because deemed interactive or soft real-time.
+ *
+ * The detection of soft real-time queues/applications is described in
+ * detail in the comments on the function
+ * bfq_bfqq_softrt_next_start. On the other hand, the detection of an
+ * interactive queue works as follows: a queue is deemed interactive
+ * if it is constantly non empty only for a limited time interval,
+ * after which it does become empty. The queue may be deemed
+ * interactive again (for a limited time), if it restarts being
+ * constantly non empty, provided that this happens only after the
+ * queue has remained empty for a given minimum idle time.
+ *
+ * By default, BFQ computes automatically the above maximum time
+ * interval, i.e., the time interval after which a constantly
+ * non-empty queue stops being deemed interactive. Since a queue is
+ * weight-raised while it is deemed interactive, this maximum time
+ * interval happens to coincide with the (maximum) duration of the
+ * weight-raising for interactive queues.
+ *
+ * Finally, BFQ also features additional heuristics for
  * preserving both a low latency and a high throughput on NCQ-capable,
  * rotational or flash-based devices, and to get the job done quickly
  * for applications consisting in many I/O-bound processes.
  *
- * BFQ is described in [1], where also a reference to the initial, more
- * theoretical paper on BFQ can be found. The interested reader can find
- * in the latter paper full details on the main algorithm, as well as
- * formulas of the guarantees and formal proofs of all the properties.
- * With respect to the version of BFQ presented in these papers, this
- * implementation adds a few more heuristics, such as the one that
- * guarantees a low latency to soft real-time applications, and a
- * hierarchical extension based on H-WF2Q+.
+ * NOTE: if the main or only goal, with a given device, is to achieve
+ * the maximum-possible throughput at all times, then do switch off
+ * all low-latency heuristics for that device, by setting low_latency
+ * to 0.
+ *
+ * BFQ is described in [1], where also a reference to the initial,
+ * more theoretical paper on BFQ can be found. The interested reader
+ * can find in the latter paper full details on the main algorithm, as
+ * well as formulas of the guarantees and formal proofs of all the
+ * properties.  With respect to the version of BFQ presented in these
+ * papers, this implementation adds a few more heuristics, such as the
+ * ones that guarantee a low latency to interactive and soft real-time
+ * applications, and a hierarchical extension based on H-WF2Q+.
  *
  * B-WF2Q+ is based on WF2Q+, which is described in [2], together with
  * H-WF2Q+, while the augmented tree used here to implement B-WF2Q+
@@ -90,6 +116,7 @@
 #include <linux/module.h>
 #include <linux/slab.h>
 #include <linux/blkdev.h>
+#include <linux/cgroup.h>
 #include <linux/elevator.h>
 #include <linux/ktime.h>
 #include <linux/rbtree.h>
@@ -101,482 +128,37 @@
 #include "blk-mq.h"
 #include "blk-mq-tag.h"
 #include "blk-mq-sched.h"
-#include <linux/blktrace_api.h>
-#include <linux/hrtimer.h>
-#include <linux/blk-cgroup.h>
-
-#define BFQ_IOPRIO_CLASSES	3
-#define BFQ_CL_IDLE_TIMEOUT	(HZ/5)
-
-#define BFQ_MIN_WEIGHT			1
-#define BFQ_MAX_WEIGHT			1000
-#define BFQ_WEIGHT_CONVERSION_COEFF	10
-
-#define BFQ_DEFAULT_QUEUE_IOPRIO	4
-
-#define BFQ_DEFAULT_GRP_WEIGHT	10
-#define BFQ_DEFAULT_GRP_IOPRIO	0
-#define BFQ_DEFAULT_GRP_CLASS	IOPRIO_CLASS_BE
-
-struct bfq_entity;
-
-/**
- * struct bfq_service_tree - per ioprio_class service tree.
- *
- * Each service tree represents a B-WF2Q+ scheduler on its own.  Each
- * ioprio_class has its own independent scheduler, and so its own
- * bfq_service_tree.  All the fields are protected by the queue lock
- * of the containing bfqd.
- */
-struct bfq_service_tree {
-	/* tree for active entities (i.e., those backlogged) */
-	struct rb_root active;
-	/* tree for idle entities (i.e., not backlogged, with V <= F_i)*/
-	struct rb_root idle;
-
-	/* idle entity with minimum F_i */
-	struct bfq_entity *first_idle;
-	/* idle entity with maximum F_i */
-	struct bfq_entity *last_idle;
-
-	/* scheduler virtual time */
-	u64 vtime;
-	/* scheduler weight sum; active and idle entities contribute to it */
-	unsigned long wsum;
-};
-
-/**
- * struct bfq_sched_data - multi-class scheduler.
- *
- * bfq_sched_data is the basic scheduler queue.  It supports three
- * ioprio_classes, and can be used either as a toplevel queue or as
- * an intermediate queue on a hierarchical setup.
- * @next_in_service points to the active entity of the sched_data
- * service trees that will be scheduled next.
- *
- * The supported ioprio_classes are the same as in CFQ, in descending
- * priority order, IOPRIO_CLASS_RT, IOPRIO_CLASS_BE, IOPRIO_CLASS_IDLE.
- * Requests from higher priority queues are served before all the
- * requests from lower priority queues; among requests of the same
- * queue requests are served according to B-WF2Q+.
- * All the fields are protected by the queue lock of the containing bfqd.
- */
-struct bfq_sched_data {
-	/* entity in service */
-	struct bfq_entity *in_service_entity;
-	/* head-of-the-line entity in the scheduler */
-	struct bfq_entity *next_in_service;
-	/* array of service trees, one per ioprio_class */
-	struct bfq_service_tree service_tree[BFQ_IOPRIO_CLASSES];
-};
-
-/**
- * struct bfq_entity - schedulable entity.
- *
... (diff truncated)
```
