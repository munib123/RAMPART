# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2262_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2262_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 90-130 of the vulnerable file.

	/* Ignore bigendian datum due to broken mastering programs */
	return get_unaligned_le16(p);
}
static inline unsigned int isonum_731(char *p)
{
	return get_unaligned_le32(p);
}
static inline unsigned int isonum_732(char *p)
{
	return get_unaligned_be32(p);
}
static inline unsigned int isonum_733(char *p)
{
	/* Ignore bigendian datum due to broken mastering programs */
	return get_unaligned_le32(p);
}
extern int iso_date(char *, int);

struct inode;		/* To make gcc happy */

extern int parse_rock_ridge_inode(struct iso_directory_record *, struct inode *);
extern int get_rock_ridge_filename(struct iso_directory_record *, char *, struct inode *);
extern int isofs_name_translate(struct iso_directory_record *, char *, struct inode *);

int get_joliet_filename(struct iso_directory_record *, unsigned char *, struct inode *);
int get_acorn_filename(struct iso_directory_record *, char *, struct inode *);

extern struct dentry *isofs_lookup(struct inode *, struct dentry *, unsigned int flags);
extern struct buffer_head *isofs_bread(struct inode *, sector_t);
extern int isofs_get_blocks(struct inode *, sector_t, struct buffer_head **, unsigned long);

extern struct inode *isofs_iget(struct super_block *sb,
                                unsigned long block,
                                unsigned long offset);

/* Because the inode number is no longer relevant to finding the
 * underlying meta-data for an inode, we are free to choose a more
 * convenient 32-bit number as the inode number.  The inode numbering
 * scheme was recommended by Sergey Vlasov and Eric Lammerts. */
static inline unsigned long isofs_get_ino(unsigned long block,
					  unsigned long offset,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,7 +107,7 @@
 
 struct inode;		/* To make gcc happy */
 
-extern int parse_rock_ridge_inode(struct iso_directory_record *, struct inode *);
+extern int parse_rock_ridge_inode(struct iso_directory_record *, struct inode *, int relocated);
 extern int get_rock_ridge_filename(struct iso_directory_record *, char *, struct inode *);
 extern int isofs_name_translate(struct iso_directory_record *, char *, struct inode *);
 
@@ -118,9 +118,24 @@
 extern struct buffer_head *isofs_bread(struct inode *, sector_t);
 extern int isofs_get_blocks(struct inode *, sector_t, struct buffer_head **, unsigned long);
 
-extern struct inode *isofs_iget(struct super_block *sb,
-                                unsigned long block,
-                                unsigned long offset);
+struct inode *__isofs_iget(struct super_block *sb,
+			   unsigned long block,
+			   unsigned long offset,
+			   int relocated);
+
+static inline struct inode *isofs_iget(struct super_block *sb,
+				       unsigned long block,
+				       unsigned long offset)
+{
+	return __isofs_iget(sb, block, offset, 0);
+}
+
+static inline struct inode *isofs_iget_reloc(struct super_block *sb,
+					     unsigned long block,
+					     unsigned long offset)
+{
+	return __isofs_iget(sb, block, offset, 1);
+}
 
 /* Because the inode number is no longer relevant to finding the
  * underlying meta-data for an inode, we are free to choose a more
```
