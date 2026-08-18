# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5397_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5397_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 692-732 of the vulnerable file.

	if (res)
		ctx->pos = *pos;

	return res;
}

static int proc_sys_readdir(struct file *file, struct dir_context *ctx)
{
	struct ctl_table_header *head = grab_header(file_inode(file));
	struct ctl_table_header *h = NULL;
	struct ctl_table *entry;
	struct ctl_dir *ctl_dir;
	unsigned long pos;

	if (IS_ERR(head))
		return PTR_ERR(head);

	ctl_dir = container_of(head, struct ctl_dir, header);

	if (!dir_emit_dots(file, ctx))
		return 0;

	pos = 2;

	for (first_entry(ctl_dir, &h, &entry); h; next_entry(&h, &entry)) {
		if (!scan(h, entry, &pos, file, ctx)) {
			sysctl_head_finish(h);
			break;
		}
	}
	sysctl_head_finish(head);
	return 0;
}

static int proc_sys_permission(struct inode *inode, int mask)
{
	/*
	 * sysctl entries that are not writeable,
	 * are _NOT_ writeable, capabilities or not.
	 */
	struct ctl_table_header *head;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -709,7 +709,7 @@
 	ctl_dir = container_of(head, struct ctl_dir, header);
 
 	if (!dir_emit_dots(file, ctx))
-		return 0;
+		goto out;
 
 	pos = 2;
 
@@ -719,6 +719,7 @@
 			break;
 		}
 	}
+out:
 	sysctl_head_finish(head);
 	return 0;
 }
```
