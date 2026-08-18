# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 1842_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1842_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 1451-1491 of the vulnerable file.

	/* Wait multiplier for lazy initialization thread */
	unsigned int s_li_wait_mult;

	/* Kernel thread for multiple mount protection */
	struct task_struct *s_mmp_tsk;

	/* record the last minlen when FITRIM is called. */
	atomic_t s_last_trim_minblks;

	/* Reference to checksum algorithm driver via cryptoapi */
	struct crypto_shash *s_chksum_driver;

	/* Precomputed FS UUID checksum for seeding other checksums */
	__u32 s_csum_seed;

	/* Reclaim extents from extent status tree */
	struct shrinker s_es_shrinker;
	struct list_head s_es_list;	/* List of inodes with reclaimable extents */
	long s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_mb_cache;
	spinlock_t s_es_lock ____cacheline_aligned_in_smp;

	/* Ratelimit ext4 messages. */
	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;
};

static inline struct ext4_sb_info *EXT4_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}
static inline struct ext4_inode_info *EXT4_I(struct inode *inode)
{
	return container_of(inode, struct ext4_inode_info, vfs_inode);
}

static inline struct timespec ext4_current_time(struct inode *inode)
{
	return (inode->i_sb->s_time_gran < NSEC_PER_SEC) ?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1468,7 +1468,7 @@
 	struct list_head s_es_list;	/* List of inodes with reclaimable extents */
 	long s_es_nr_inode;
 	struct ext4_es_stats s_es_stats;
-	struct mb_cache *s_mb_cache;
+	struct mb2_cache *s_mb_cache;
 	spinlock_t s_es_lock ____cacheline_aligned_in_smp;
 
 	/* Ratelimit ext4 messages. */
```
