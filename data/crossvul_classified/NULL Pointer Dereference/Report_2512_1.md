# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2512_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2512_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 98-136 of the vulnerable file.

	 */
	handle_cmd_fn_t handle_cmd;

	/*
	 * Below callbacks are only exected called by generic_handle_cmd.
	 * Returns:
	 * - 0 if the handler has queued the command.
	 * - SAM_STAT_TASK_SET_FULL if the handler was not able to allocate
	 *   resources for the command.
	 *
	 * If 0 is returned the handler must call the tcmulib_cmd->done
	 * function with SAM_STAT_GOOD or a SAM status code and set the
	 * the sense asc/ascq if needed.
	 */
	rw_fn_t write;
	rw_fn_t read;
	flush_fn_t flush;
	int (*lock)(struct tcmu_device *dev);
	int (*unlock)(struct tcmu_device *dev);
	int (*has_lock)(struct tcmu_device *dev);
};

/*
 * Each tcmu-runner (tcmur) handler plugin must export the
 * following. It usually just calls tcmur_register_handler.
 */
void tcmur_handler_init(void);

/*
 * APIs for tcmur only
 */
int tcmur_register_handler(struct tcmur_handler *handler);
bool tcmur_unregister_handler(struct tcmur_handler *handler);

#ifdef __cplusplus
}
#endif

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,6 +115,15 @@
 	int (*lock)(struct tcmu_device *dev);
 	int (*unlock)(struct tcmu_device *dev);
 	int (*has_lock)(struct tcmu_device *dev);
+
+	/*
+	 * internal field, don't touch this
+	 *
+	 * indicates to tcmu-runner whether this is an internal handler loaded
+	 * via dlopen or an external handler registered via dbus. In the
+	 * latter case opaque will point to a struct dbus_info.
+	 */
+	bool _is_dbus_handler;
 };
 
 /*
```
