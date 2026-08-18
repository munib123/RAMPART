# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1427_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1427_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1167-1207 of the vulnerable file.

	}
	srcu_read_unlock(&ipmi_interfaces_srcu, index);

	/* Not found, return an error */
	return -EINVAL;

found:
	if (!intf->handlers->get_smi_info)
		rv = -ENOTTY;
	else
		rv = intf->handlers->get_smi_info(intf->send_info, data);
	srcu_read_unlock(&ipmi_interfaces_srcu, index);

	return rv;
}
EXPORT_SYMBOL(ipmi_get_smi_info);

static void free_user(struct kref *ref)
{
	struct ipmi_user *user = container_of(ref, struct ipmi_user, refcount);
	kfree(user);
}

static void _ipmi_destroy_user(struct ipmi_user *user)
{
	struct ipmi_smi  *intf = user->intf;
	int              i;
	unsigned long    flags;
	struct cmd_rcvr  *rcvr;
	struct cmd_rcvr  *rcvrs = NULL;

	if (!acquire_ipmi_user(user, &i)) {
		/*
		 * The user has already been cleaned up, just make sure
		 * nothing is using it and return.
		 */
		synchronize_srcu(&user->release_barrier);
		return;
	}

	rcu_assign_pointer(user->self, NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1184,6 +1184,7 @@
 static void free_user(struct kref *ref)
 {
 	struct ipmi_user *user = container_of(ref, struct ipmi_user, refcount);
+	cleanup_srcu_struct(&user->release_barrier);
 	kfree(user);
 }
 
@@ -1260,7 +1261,6 @@
 {
 	_ipmi_destroy_user(user);
 
-	cleanup_srcu_struct(&user->release_barrier);
 	kref_put(&user->refcount, free_user);
 
 	return 0;
```
