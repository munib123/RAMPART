# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4729_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4729_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 28-70 of the vulnerable file.

		.cputime = INIT_CPUTIME,				\
		.running = 0,						\
		.lock = __SPIN_LOCK_UNLOCKED(sig.cputimer.lock),	\
	},								\
}

extern struct nsproxy init_nsproxy;

#define INIT_SIGHAND(sighand) {						\
	.count		= ATOMIC_INIT(1), 				\
	.action		= { { { .sa_handler = NULL, } }, },		\
	.siglock	= __SPIN_LOCK_UNLOCKED(sighand.siglock),	\
	.signalfd_wqh	= __WAIT_QUEUE_HEAD_INITIALIZER(sighand.signalfd_wqh),	\
}

extern struct group_info init_groups;

#define INIT_STRUCT_PID {						\
	.count 		= ATOMIC_INIT(1),				\
	.tasks		= {						\
		{ .first = &init_task.pids[PIDTYPE_PID].node },		\
		{ .first = &init_task.pids[PIDTYPE_PGID].node },	\
		{ .first = &init_task.pids[PIDTYPE_SID].node },		\
	},								\
	.level		= 0,						\
	.numbers	= { {						\
		.nr		= 0,					\
		.ns		= &init_pid_ns,				\
		.pid_chain	= { .next = NULL, .pprev = NULL },	\
	}, }								\
}

#define INIT_PID_LINK(type) 					\
{								\
	.node = {						\
		.next = NULL,					\
		.pprev = &init_struct_pid.tasks[type].first,	\
	},							\
	.pid = &init_struct_pid,				\
}

#ifdef CONFIG_AUDITSYSCALL
#define INIT_IDS \
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,9 +45,9 @@
 #define INIT_STRUCT_PID {						\
 	.count 		= ATOMIC_INIT(1),				\
 	.tasks		= {						\
-		{ .first = &init_task.pids[PIDTYPE_PID].node },		\
-		{ .first = &init_task.pids[PIDTYPE_PGID].node },	\
-		{ .first = &init_task.pids[PIDTYPE_SID].node },		\
+		{ .first = NULL },					\
+		{ .first = NULL },					\
+		{ .first = NULL },					\
 	},								\
 	.level		= 0,						\
 	.numbers	= { {						\
@@ -61,7 +61,7 @@
 {								\
 	.node = {						\
 		.next = NULL,					\
-		.pprev = &init_struct_pid.tasks[type].first,	\
+		.pprev = NULL,					\
 	},							\
 	.pid = &init_struct_pid,				\
 }
```
