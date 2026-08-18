# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3012_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3012_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1193-1233 of the vulnerable file.

	}
	mutex_unlock(&dcc->cmd_lock);

	if (need_wait)
		__wait_one_discard_bio(sbi, dc);
}

void stop_discard_thread(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;

	if (dcc && dcc->f2fs_issue_discard) {
		struct task_struct *discard_thread = dcc->f2fs_issue_discard;

		dcc->f2fs_issue_discard = NULL;
		kthread_stop(discard_thread);
	}
}

/* This comes from f2fs_put_super and f2fs_trim_fs */
void f2fs_wait_discard_bios(struct f2fs_sb_info *sbi)
{
	__issue_discard_cmd(sbi, false);
	__drop_discard_cmd(sbi);
	__wait_discard_cmd(sbi, false);
}

static void mark_discard_range_all(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	int i;

	mutex_lock(&dcc->cmd_lock);
	for (i = 0; i < MAX_PLIST_NUM; i++)
		dcc->pend_list_tag[i] |= P_TRIM;
	mutex_unlock(&dcc->cmd_lock);
}

static int issue_discard_thread(void *data)
{
	struct f2fs_sb_info *sbi = data;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1210,11 +1210,11 @@
 }
 
 /* This comes from f2fs_put_super and f2fs_trim_fs */
-void f2fs_wait_discard_bios(struct f2fs_sb_info *sbi)
+void f2fs_wait_discard_bios(struct f2fs_sb_info *sbi, bool umount)
 {
 	__issue_discard_cmd(sbi, false);
 	__drop_discard_cmd(sbi);
-	__wait_discard_cmd(sbi, false);
+	__wait_discard_cmd(sbi, !umount);
 }
 
 static void mark_discard_range_all(struct f2fs_sb_info *sbi)
@@ -2244,7 +2244,7 @@
 	}
 	/* It's time to issue all the filed discards */
 	mark_discard_range_all(sbi);
-	f2fs_wait_discard_bios(sbi);
+	f2fs_wait_discard_bios(sbi, false);
 out:
 	range->len = F2FS_BLK_TO_BYTES(cpc.trimmed);
 	return err;
```
