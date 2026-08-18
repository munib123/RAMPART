# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3471_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3471_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 67-107 of the vulnerable file.

						 * be any workqueue
						 */
	struct rpc_wait_queue 	*tk_waitqueue;	/* RPC wait queue we're on */
	union {
		struct work_struct	tk_work;	/* Async task work queue */
		struct rpc_wait		tk_wait;	/* RPC wait */
	} u;

	ktime_t			tk_start;	/* RPC task init timestamp */

	pid_t			tk_owner;	/* Process id for batching tasks */
	int			tk_status;	/* result of last operation */
	unsigned short		tk_flags;	/* misc flags */
	unsigned short		tk_timeouts;	/* maj timeouts */

#ifdef RPC_DEBUG
	unsigned short		tk_pid;		/* debugging aid */
#endif
	unsigned char		tk_priority : 2,/* Task priority */
				tk_garb_retry : 2,
				tk_cred_retry : 2;
};
#define tk_xprt			tk_client->cl_xprt

/* support walking a list of tasks on a wait queue */
#define	task_for_each(task, pos, head) \
	list_for_each(pos, head) \
		if ((task=list_entry(pos, struct rpc_task, u.tk_wait.list)),1)

#define	task_for_first(task, head) \
	if (!list_empty(head) &&  \
	    ((task=list_entry((head)->next, struct rpc_task, u.tk_wait.list)),1))

typedef void			(*rpc_action)(struct rpc_task *);

struct rpc_call_ops {
	void (*rpc_call_prepare)(struct rpc_task *, void *);
	void (*rpc_call_done)(struct rpc_task *, void *);
	void (*rpc_release)(void *);
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,7 +84,8 @@
 #endif
 	unsigned char		tk_priority : 2,/* Task priority */
 				tk_garb_retry : 2,
-				tk_cred_retry : 2;
+				tk_cred_retry : 2,
+				tk_rebind_retry : 2;
 };
 #define tk_xprt			tk_client->cl_xprt
 
```
