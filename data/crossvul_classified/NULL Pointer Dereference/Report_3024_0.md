# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3024_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3024_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 549-589 of the vulnerable file.


int create_flush_cmd_control(struct f2fs_sb_info *sbi)
{
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	struct flush_cmd_control *fcc;
	int err = 0;

	if (SM_I(sbi)->fcc_info) {
		fcc = SM_I(sbi)->fcc_info;
		goto init_thread;
	}

	fcc = kzalloc(sizeof(struct flush_cmd_control), GFP_KERNEL);
	if (!fcc)
		return -ENOMEM;
	atomic_set(&fcc->issued_flush, 0);
	atomic_set(&fcc->issing_flush, 0);
	init_waitqueue_head(&fcc->flush_wait_queue);
	init_llist_head(&fcc->issue_list);
	SM_I(sbi)->fcc_info = fcc;
init_thread:
	fcc->f2fs_issue_flush = kthread_run(issue_flush_thread, sbi,
				"f2fs_flush-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(fcc->f2fs_issue_flush)) {
		err = PTR_ERR(fcc->f2fs_issue_flush);
		kfree(fcc);
		SM_I(sbi)->fcc_info = NULL;
		return err;
	}

	return err;
}

void destroy_flush_cmd_control(struct f2fs_sb_info *sbi, bool free)
{
	struct flush_cmd_control *fcc = SM_I(sbi)->fcc_info;

	if (fcc && fcc->f2fs_issue_flush) {
		struct task_struct *flush_thread = fcc->f2fs_issue_flush;

		fcc->f2fs_issue_flush = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -566,6 +566,9 @@
 	init_waitqueue_head(&fcc->flush_wait_queue);
 	init_llist_head(&fcc->issue_list);
 	SM_I(sbi)->fcc_info = fcc;
+	if (!test_opt(sbi, FLUSH_MERGE))
+		return err;
+
 init_thread:
 	fcc->f2fs_issue_flush = kthread_run(issue_flush_thread, sbi,
 				"f2fs_flush-%u:%u", MAJOR(dev), MINOR(dev));
@@ -3240,7 +3243,7 @@
 
 	INIT_LIST_HEAD(&sm_info->sit_entry_set);
 
-	if (test_opt(sbi, FLUSH_MERGE) && !f2fs_readonly(sbi->sb)) {
+	if (!f2fs_readonly(sbi->sb)) {
 		err = create_flush_cmd_control(sbi);
 		if (err)
 			return err;
```
