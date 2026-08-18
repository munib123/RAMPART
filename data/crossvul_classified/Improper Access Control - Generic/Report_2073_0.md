# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2073_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2073_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 3104-3144 of the vulnerable file.

		kfree(this);
		this = next;
	}
}

static int raw_cmd_copyin(int cmd, void __user *param,
				 struct floppy_raw_cmd **rcmd)
{
	struct floppy_raw_cmd *ptr;
	int ret;
	int i;

	*rcmd = NULL;

loop:
	ptr = kmalloc(sizeof(struct floppy_raw_cmd), GFP_USER);
	if (!ptr)
		return -ENOMEM;
	*rcmd = ptr;
	ret = copy_from_user(ptr, param, sizeof(*ptr));
	if (ret)
		return -EFAULT;
	ptr->next = NULL;
	ptr->buffer_length = 0;
	param += sizeof(struct floppy_raw_cmd);
	if (ptr->cmd_count > 33)
			/* the command may now also take up the space
			 * initially intended for the reply & the
			 * reply count. Needed for long 82078 commands
			 * such as RESTORE, which takes ... 17 command
			 * bytes. Murphy's law #137: When you reserve
			 * 16 bytes for a structure, you'll one day
			 * discover that you really need 17...
			 */
		return -EINVAL;

	for (i = 0; i < 16; i++)
		ptr->reply[i] = 0;
	ptr->resultcode = 0;
	ptr->kernel_data = NULL;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3121,10 +3121,11 @@
 		return -ENOMEM;
 	*rcmd = ptr;
 	ret = copy_from_user(ptr, param, sizeof(*ptr));
+	ptr->next = NULL;
+	ptr->buffer_length = 0;
+	ptr->kernel_data = NULL;
 	if (ret)
 		return -EFAULT;
-	ptr->next = NULL;
-	ptr->buffer_length = 0;
 	param += sizeof(struct floppy_raw_cmd);
 	if (ptr->cmd_count > 33)
 			/* the command may now also take up the space
@@ -3140,7 +3141,6 @@
 	for (i = 0; i < 16; i++)
 		ptr->reply[i] = 0;
 	ptr->resultcode = 0;
-	ptr->kernel_data = NULL;
 
 	if (ptr->flags & (FD_RAW_READ | FD_RAW_WRITE)) {
 		if (ptr->length <= 0)
```
