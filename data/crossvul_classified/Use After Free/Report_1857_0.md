# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1857_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1857_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 71-111 of the vulnerable file.

		return ERR_PTR(err);

	journal = EXT4_SB(sb)->s_journal;
	if (!journal)
		return ext4_get_nojournal();
	return jbd2__journal_start(journal, blocks, rsv_blocks, GFP_NOFS,
				   type, line);
}

int __ext4_journal_stop(const char *where, unsigned int line, handle_t *handle)
{
	struct super_block *sb;
	int err;
	int rc;

	if (!ext4_handle_valid(handle)) {
		ext4_put_nojournal(handle);
		return 0;
	}

	if (!handle->h_transaction) {
		err = jbd2_journal_stop(handle);
		return handle->h_err ? handle->h_err : err;
	}

	sb = handle->h_transaction->t_journal->j_private;
	err = handle->h_err;
	rc = jbd2_journal_stop(handle);

	if (!err)
		err = rc;
	if (err)
		__ext4_std_error(sb, where, line, err);
	return err;
}

handle_t *__ext4_journal_start_reserved(handle_t *handle, unsigned int line,
					int type)
{
	struct super_block *sb;
	int err;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,13 +88,13 @@
 		return 0;
 	}
 
+	err = handle->h_err;
 	if (!handle->h_transaction) {
-		err = jbd2_journal_stop(handle);
-		return handle->h_err ? handle->h_err : err;
+		rc = jbd2_journal_stop(handle);
+		return err ? err : rc;
 	}
 
 	sb = handle->h_transaction->t_journal->j_private;
-	err = handle->h_err;
 	rc = jbd2_journal_stop(handle);
 
 	if (!err)
```
