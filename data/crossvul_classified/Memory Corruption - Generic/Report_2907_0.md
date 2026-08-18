# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2907_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2907_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 285-326 of the vulnerable file.

			evt = list_first_entry(&rc->uwbd.event_list, struct uwb_event, list_node);
			list_del(&evt->list_node);
		} else
			evt = NULL;
		spin_unlock_irqrestore(&rc->uwbd.event_list_lock, flags);

		if (evt) {
			uwbd_event_handle(evt);
			kfree(evt);
		}

		uwb_beca_purge(rc);	/* Purge devices that left */
	}
	return 0;
}


/** Start the UWB daemon */
void uwbd_start(struct uwb_rc *rc)
{
	rc->uwbd.task = kthread_run(uwbd, rc, "uwbd");
	if (rc->uwbd.task == NULL)
		printk(KERN_ERR "UWB: Cannot start management daemon; "
		       "UWB won't work\n");
	else
		rc->uwbd.pid = rc->uwbd.task->pid;
}

/* Stop the UWB daemon and free any unprocessed events */
void uwbd_stop(struct uwb_rc *rc)
{
	kthread_stop(rc->uwbd.task);
	uwbd_flush(rc);
}

/*
 * Queue an event for the management daemon
 *
 * When some lower layer receives an event, it uses this function to
 * push it forward to the UWB daemon.
 *
 * Once you pass the event, you don't own it any more, but the daemon
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -302,18 +302,22 @@
 /** Start the UWB daemon */
 void uwbd_start(struct uwb_rc *rc)
 {
-	rc->uwbd.task = kthread_run(uwbd, rc, "uwbd");
-	if (rc->uwbd.task == NULL)
+	struct task_struct *task = kthread_run(uwbd, rc, "uwbd");
+	if (IS_ERR(task)) {
+		rc->uwbd.task = NULL;
 		printk(KERN_ERR "UWB: Cannot start management daemon; "
 		       "UWB won't work\n");
-	else
+	} else {
+		rc->uwbd.task = task;
 		rc->uwbd.pid = rc->uwbd.task->pid;
+	}
 }
 
 /* Stop the UWB daemon and free any unprocessed events */
 void uwbd_stop(struct uwb_rc *rc)
 {
-	kthread_stop(rc->uwbd.task);
+	if (rc->uwbd.task)
+		kthread_stop(rc->uwbd.task);
 	uwbd_flush(rc);
 }
 
```
