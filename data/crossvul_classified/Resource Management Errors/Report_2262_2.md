# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2262_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2262_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 271-311 of the vulnerable file.

		case SIG('R', 'E'):
			kfree(rs.buffer);
			return -1;
		default:
			break;
		}
	}
	ret = rock_continue(&rs);
	if (ret == 0)
		goto repeat;
	if (ret == 1)
		return retnamlen; /* If 0, this file did not have a NM field */
out:
	kfree(rs.buffer);
	return ret;
eio:
	ret = -EIO;
	goto out;
}

static int
parse_rock_ridge_inode_internal(struct iso_directory_record *de,
				struct inode *inode, int regard_xa)
{
	int symlink_len = 0;
	int cnt, sig;
	struct inode *reloc;
	struct rock_ridge *rr;
	int rootflag;
	struct rock_state rs;
	int ret = 0;

	if (!ISOFS_SB(inode->i_sb)->s_rock)
		return 0;

	init_rock_state(&rs, inode);
	setup_rock_ridge(de, inode, &rs);
	if (regard_xa) {
		rs.chr += 14;
		rs.len -= 14;
		if (rs.len < 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -288,12 +288,16 @@
 	goto out;
 }
 
+#define RR_REGARD_XA 1
+#define RR_RELOC_DE 2
+
 static int
 parse_rock_ridge_inode_internal(struct iso_directory_record *de,
-				struct inode *inode, int regard_xa)
+				struct inode *inode, int flags)
 {
 	int symlink_len = 0;
 	int cnt, sig;
+	unsigned int reloc_block;
 	struct inode *reloc;
 	struct rock_ridge *rr;
 	int rootflag;
@@ -305,7 +309,7 @@
 
 	init_rock_state(&rs, inode);
 	setup_rock_ridge(de, inode, &rs);
-	if (regard_xa) {
+	if (flags & RR_REGARD_XA) {
 		rs.chr += 14;
 		rs.len -= 14;
 		if (rs.len < 0)
@@ -485,12 +489,22 @@
 					"relocated directory\n");
 			goto out;
 		case SIG('C', 'L'):
-			ISOFS_I(inode)->i_first_extent =
-			    isonum_733(rr->u.CL.location);
-			reloc =
-			    isofs_iget(inode->i_sb,
-				       ISOFS_I(inode)->i_first_extent,
-				       0);
+			if (flags & RR_RELOC_DE) {
+				printk(KERN_ERR
+				       "ISOFS: Recursive directory relocation "
+				       "is not supported\n");
+				goto eio;
+			}
+			reloc_block = isonum_733(rr->u.CL.location);
+			if (reloc_block == ISOFS_I(inode)->i_iget5_block &&
+			    ISOFS_I(inode)->i_iget5_offset == 0) {
+				printk(KERN_ERR
+				       "ISOFS: Directory relocation points to "
+				       "itself\n");
+				goto eio;
+			}
+			ISOFS_I(inode)->i_first_extent = reloc_block;
+			reloc = isofs_iget_reloc(inode->i_sb, reloc_block, 0);
 			if (IS_ERR(reloc)) {
 				ret = PTR_ERR(reloc);
 				goto out;
@@ -637,9 +651,11 @@
 	return rpnt;
 }
 
-int parse_rock_ridge_inode(struct iso_directory_record *de, struct inode *inode)
-{
-	int result = parse_rock_ridge_inode_internal(de, inode, 0);
+int parse_rock_ridge_inode(struct iso_directory_record *de, struct inode *inode,
+			   int relocated)
+{
+	int flags = relocated ? RR_RELOC_DE : 0;
+	int result = parse_rock_ridge_inode_internal(de, inode, flags);
 
 	/*
 	 * if rockridge flag was reset and we didn't look for attributes
@@ -647,7 +663,8 @@
 	 */
 	if ((ISOFS_SB(inode->i_sb)->s_rock_offset == -1)
 	    && (ISOFS_SB(inode->i_sb)->s_rock == 2)) {
-		result = parse_rock_ridge_inode_internal(de, inode, 14);
+		result = parse_rock_ridge_inode_internal(de, inode,
+							 flags | RR_REGARD_XA);
 	}
 	return result;
 }
```
