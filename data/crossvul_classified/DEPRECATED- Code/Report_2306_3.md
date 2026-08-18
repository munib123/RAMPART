# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 2306_3
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2306_3`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 123-165 of the vulnerable file.

						 sc->nid);
	total_objects += list_lru_count_node(&sb->s_inode_lru,
						 sc->nid);

	total_objects = vfs_pressure_ratio(total_objects);
	drop_super(sb);
	return total_objects;
}

/**
 *	destroy_super	-	frees a superblock
 *	@s: superblock to free
 *
 *	Frees a superblock.
 */
static void destroy_super(struct super_block *s)
{
	int i;
	list_lru_destroy(&s->s_dentry_lru);
	list_lru_destroy(&s->s_inode_lru);
#ifdef CONFIG_SMP
	free_percpu(s->s_files);
#endif
	for (i = 0; i < SB_FREEZE_LEVELS; i++)
		percpu_counter_destroy(&s->s_writers.counter[i]);
	security_sb_free(s);
	WARN_ON(!list_empty(&s->s_mounts));
	kfree(s->s_subtype);
	kfree(s->s_options);
	kfree_rcu(s, rcu);
}

/**
 *	alloc_super	-	create new superblock
 *	@type:	filesystem type superblock should belong to
 *	@flags: the mount flags
 *
 *	Allocates and initializes a new &struct super_block.  alloc_super()
 *	returns a pointer new superblock or %NULL if allocation had failed.
 */
static struct super_block *alloc_super(struct file_system_type *type, int flags)
{
	struct super_block *s = kzalloc(sizeof(struct super_block),  GFP_USER);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -140,9 +140,6 @@
 	int i;
 	list_lru_destroy(&s->s_dentry_lru);
 	list_lru_destroy(&s->s_inode_lru);
-#ifdef CONFIG_SMP
-	free_percpu(s->s_files);
-#endif
 	for (i = 0; i < SB_FREEZE_LEVELS; i++)
 		percpu_counter_destroy(&s->s_writers.counter[i]);
 	security_sb_free(s);
@@ -172,15 +169,6 @@
 	if (security_sb_alloc(s))
 		goto fail;
 
-#ifdef CONFIG_SMP
-	s->s_files = alloc_percpu(struct list_head);
-	if (!s->s_files)
-		goto fail;
-	for_each_possible_cpu(i)
-		INIT_LIST_HEAD(per_cpu_ptr(s->s_files, i));
-#else
-	INIT_LIST_HEAD(&s->s_files);
-#endif
 	for (i = 0; i < SB_FREEZE_LEVELS; i++) {
 		if (percpu_counter_init(&s->s_writers.counter[i], 0) < 0)
 			goto fail;
@@ -722,7 +710,8 @@
 	   make sure there are no rw files opened */
 	if (remount_ro) {
 		if (force) {
-			mark_files_ro(sb);
+			sb->s_readonly_remount = 1;
+			smp_wmb();
 		} else {
 			retval = sb_prepare_remount_readonly(sb);
 			if (retval)
```
