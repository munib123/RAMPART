# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2262_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2262_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 44-84 of the vulnerable file.

		const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name);
static int isofs_dentry_cmp_ms(const struct dentry *parent,
		const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name);
#endif

static void isofs_put_super(struct super_block *sb)
{
	struct isofs_sb_info *sbi = ISOFS_SB(sb);

#ifdef CONFIG_JOLIET
	unload_nls(sbi->s_nls_iocharset);
#endif

	kfree(sbi);
	sb->s_fs_info = NULL;
	return;
}

static int isofs_read_inode(struct inode *);
static int isofs_statfs (struct dentry *, struct kstatfs *);

static struct kmem_cache *isofs_inode_cachep;

static struct inode *isofs_alloc_inode(struct super_block *sb)
{
	struct iso_inode_info *ei;
	ei = kmem_cache_alloc(isofs_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void isofs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(isofs_inode_cachep, ISOFS_I(inode));
}

static void isofs_destroy_inode(struct inode *inode)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,7 +61,7 @@
 	return;
 }
 
-static int isofs_read_inode(struct inode *);
+static int isofs_read_inode(struct inode *, int relocated);
 static int isofs_statfs (struct dentry *, struct kstatfs *);
 
 static struct kmem_cache *isofs_inode_cachep;
@@ -1259,7 +1259,7 @@
 	goto out;
 }
 
-static int isofs_read_inode(struct inode *inode)
+static int isofs_read_inode(struct inode *inode, int relocated)
 {
 	struct super_block *sb = inode->i_sb;
 	struct isofs_sb_info *sbi = ISOFS_SB(sb);
@@ -1404,7 +1404,7 @@
 	 */
 
 	if (!high_sierra) {
-		parse_rock_ridge_inode(de, inode);
+		parse_rock_ridge_inode(de, inode, relocated);
 		/* if we want uid/gid set, override the rock ridge setting */
 		if (sbi->s_uid_set)
 			inode->i_uid = sbi->s_uid;
@@ -1483,9 +1483,10 @@
  * offset that point to the underlying meta-data for the inode.  The
  * code below is otherwise similar to the iget() code in
  * include/linux/fs.h */
-struct inode *isofs_iget(struct super_block *sb,
-			 unsigned long block,
-			 unsigned long offset)
+struct inode *__isofs_iget(struct super_block *sb,
+			   unsigned long block,
+			   unsigned long offset,
+			   int relocated)
 {
 	unsigned long hashval;
 	struct inode *inode;
@@ -1507,7 +1508,7 @@
 		return ERR_PTR(-ENOMEM);
 
 	if (inode->i_state & I_NEW) {
-		ret = isofs_read_inode(inode);
+		ret = isofs_read_inode(inode, relocated);
 		if (ret < 0) {
 			iget_failed(inode);
 			inode = ERR_PTR(ret);
```
