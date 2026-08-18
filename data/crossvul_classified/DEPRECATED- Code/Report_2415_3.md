# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 2415_3
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2415_3`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 194-234 of the vulnerable file.

			       uint32_t);
extern uint32_t udf_get_pblock_virt15(struct super_block *, uint32_t, uint16_t,
				      uint32_t);
extern uint32_t udf_get_pblock_virt20(struct super_block *, uint32_t, uint16_t,
				      uint32_t);
extern uint32_t udf_get_pblock_spar15(struct super_block *, uint32_t, uint16_t,
				      uint32_t);
extern uint32_t udf_get_pblock_meta25(struct super_block *, uint32_t, uint16_t,
					  uint32_t);
extern int udf_relocate_blocks(struct super_block *, long, long *);

static inline uint32_t
udf_get_lb_pblock(struct super_block *sb, struct kernel_lb_addr *loc,
		  uint32_t offset)
{
	return udf_get_pblock(sb, loc->logicalBlockNum,
			loc->partitionReferenceNum, offset);
}

/* unicode.c */
extern int udf_get_filename(struct super_block *, uint8_t *, uint8_t *, int);
extern int udf_put_filename(struct super_block *, const uint8_t *, uint8_t *,
			    int);
extern int udf_build_ustr(struct ustr *, dstring *, int);
extern int udf_CS0toUTF8(struct ustr *, const struct ustr *);

/* ialloc.c */
extern void udf_free_inode(struct inode *);
extern struct inode *udf_new_inode(struct inode *, umode_t);

/* truncate.c */
extern void udf_truncate_tail_extent(struct inode *);
extern void udf_discard_prealloc(struct inode *);
extern void udf_truncate_extents(struct inode *);

/* balloc.c */
extern void udf_free_blocks(struct super_block *, struct inode *,
			    struct kernel_lb_addr *, uint32_t, uint32_t);
extern int udf_prealloc_blocks(struct super_block *, struct inode *, uint16_t,
			       uint32_t, uint32_t);
extern int udf_new_block(struct super_block *, struct inode *, uint16_t,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -211,7 +211,8 @@
 }
 
 /* unicode.c */
-extern int udf_get_filename(struct super_block *, uint8_t *, uint8_t *, int);
+extern int udf_get_filename(struct super_block *, uint8_t *, int, uint8_t *,
+			    int);
 extern int udf_put_filename(struct super_block *, const uint8_t *, uint8_t *,
 			    int);
 extern int udf_build_ustr(struct ustr *, dstring *, int);
```
