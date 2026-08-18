# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 4747_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4747_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1308-1348 of the vulnerable file.

		copied += len;
		buf += len;
		count -= len;
	}
	*ppos += copied;
	if (!ret || ret == PM_END_OF_BUFFER)
		ret = copied;

out_mm:
	mmput(mm);
out_free:
	kfree(pm.buffer);
out_task:
	put_task_struct(task);
out:
	return ret;
}

static int pagemap_open(struct inode *inode, struct file *file)
{
	pr_warn_once("Bits 55-60 of /proc/PID/pagemap entries are about "
			"to stop being page-shift some time soon. See the "
			"linux/Documentation/vm/pagemap.txt for details.\n");
	return 0;
}

const struct file_operations proc_pagemap_operations = {
	.llseek		= mem_lseek, /* borrow this */
	.read		= pagemap_read,
	.open		= pagemap_open,
};
#endif /* CONFIG_PROC_PAGE_MONITOR */

#ifdef CONFIG_NUMA

struct numa_maps {
	unsigned long pages;
	unsigned long anon;
	unsigned long active;
	unsigned long writeback;
	unsigned long mapcount_max;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1325,6 +1325,9 @@
 
 static int pagemap_open(struct inode *inode, struct file *file)
 {
+	/* do not disclose physical addresses: attack vector */
+	if (!capable(CAP_SYS_ADMIN))
+		return -EPERM;
 	pr_warn_once("Bits 55-60 of /proc/PID/pagemap entries are about "
 			"to stop being page-shift some time soon. See the "
 			"linux/Documentation/vm/pagemap.txt for details.\n");
```
