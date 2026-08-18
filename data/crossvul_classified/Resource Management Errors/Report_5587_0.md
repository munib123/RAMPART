# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5587_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5587_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 2469-2509 of the vulnerable file.

			       this_char);
			return 1;
		}
	}
	return 0;

bad_val:
	printk(KERN_ERR "tmpfs: Bad value '%s' for mount option '%s'\n",
	       value, this_char);
	return 1;

}

static int shmem_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	struct shmem_sb_info config = *sbinfo;
	unsigned long inodes;
	int error = -EINVAL;

	if (shmem_parse_options(data, &config, true))
		return error;

	spin_lock(&sbinfo->stat_lock);
	inodes = sbinfo->max_inodes - sbinfo->free_inodes;
	if (percpu_counter_compare(&sbinfo->used_blocks, config.max_blocks) > 0)
		goto out;
	if (config.max_inodes < inodes)
		goto out;
	/*
	 * Those tests disallow limited->unlimited while any are in use;
	 * but we must separately disallow unlimited->limited, because
	 * in that case we have no record of how much is already in use.
	 */
	if (config.max_blocks && !sbinfo->max_blocks)
		goto out;
	if (config.max_inodes && !sbinfo->max_inodes)
		goto out;

	error = 0;
	sbinfo->max_blocks  = config.max_blocks;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2486,6 +2486,7 @@
 	unsigned long inodes;
 	int error = -EINVAL;
 
+	config.mpol = NULL;
 	if (shmem_parse_options(data, &config, true))
 		return error;
 
@@ -2510,8 +2511,13 @@
 	sbinfo->max_inodes  = config.max_inodes;
 	sbinfo->free_inodes = config.max_inodes - inodes;
 
-	mpol_put(sbinfo->mpol);
-	sbinfo->mpol        = config.mpol;	/* transfers initial ref */
+	/*
+	 * Preserve previous mempolicy unless mpol remount option was specified.
+	 */
+	if (config.mpol) {
+		mpol_put(sbinfo->mpol);
+		sbinfo->mpol = config.mpol;	/* transfers initial ref */
+	}
 out:
 	spin_unlock(&sbinfo->stat_lock);
 	return error;
```
