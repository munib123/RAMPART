# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1766_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1766_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 93-133 of the vulnerable file.

 * ioctl the mgmt/dpa device
 */

long dgnc_mgmt_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long flags;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case DIGI_GETDD:
	{
		/*
		 * This returns the total number of boards
		 * in the system, as well as driver version
		 * and has space for a reserved entry
		 */
		struct digi_dinfo ddi;

		spin_lock_irqsave(&dgnc_global_lock, flags);

		ddi.dinfo_nboards = dgnc_NumBoards;
		sprintf(ddi.dinfo_version, "%s", DG_PART);

		spin_unlock_irqrestore(&dgnc_global_lock, flags);

		if (copy_to_user(uarg, &ddi, sizeof(ddi)))
			return -EFAULT;

		break;
	}

	case DIGI_GETBD:
	{
		int brd;

		struct digi_info di;

		if (copy_from_user(&brd, uarg, sizeof(int)))
			return -EFAULT;

		if (brd < 0 || brd >= dgnc_NumBoards)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,6 +110,7 @@
 
 		spin_lock_irqsave(&dgnc_global_lock, flags);
 
+		memset(&ddi, 0, sizeof(ddi));
 		ddi.dinfo_nboards = dgnc_NumBoards;
 		sprintf(ddi.dinfo_version, "%s", DG_PART);
 
```
