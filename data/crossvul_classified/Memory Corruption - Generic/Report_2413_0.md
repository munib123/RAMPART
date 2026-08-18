# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2413_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2413_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1472-1512 of the vulnerable file.

		if (!udf_disk_stamp_to_time(&inode->i_atime, efe->accessTime))
			inode->i_atime = sbi->s_record_time;

		if (!udf_disk_stamp_to_time(&inode->i_mtime,
					    efe->modificationTime))
			inode->i_mtime = sbi->s_record_time;

		if (!udf_disk_stamp_to_time(&iinfo->i_crtime, efe->createTime))
			iinfo->i_crtime = sbi->s_record_time;

		if (!udf_disk_stamp_to_time(&inode->i_ctime, efe->attrTime))
			inode->i_ctime = sbi->s_record_time;

		iinfo->i_unique = le64_to_cpu(efe->uniqueID);
		iinfo->i_lenEAttr = le32_to_cpu(efe->lengthExtendedAttr);
		iinfo->i_lenAlloc = le32_to_cpu(efe->lengthAllocDescs);
		iinfo->i_checkpoint = le32_to_cpu(efe->checkpoint);
	}
	inode->i_generation = iinfo->i_unique;

	switch (fe->icbTag.fileType) {
	case ICBTAG_FILE_TYPE_DIRECTORY:
		inode->i_op = &udf_dir_inode_operations;
		inode->i_fop = &udf_dir_operations;
		inode->i_mode |= S_IFDIR;
		inc_nlink(inode);
		break;
	case ICBTAG_FILE_TYPE_REALTIME:
	case ICBTAG_FILE_TYPE_REGULAR:
	case ICBTAG_FILE_TYPE_UNDEF:
	case ICBTAG_FILE_TYPE_VAT20:
		if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
			inode->i_data.a_ops = &udf_adinicb_aops;
		else
			inode->i_data.a_ops = &udf_aops;
		inode->i_op = &udf_file_inode_operations;
		inode->i_fop = &udf_file_operations;
		inode->i_mode |= S_IFREG;
		break;
	case ICBTAG_FILE_TYPE_BLOCK:
		inode->i_mode |= S_IFBLK;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1488,6 +1488,20 @@
 		iinfo->i_checkpoint = le32_to_cpu(efe->checkpoint);
 	}
 	inode->i_generation = iinfo->i_unique;
+
+	/* Sanity checks for files in ICB so that we don't get confused later */
+	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
+		/*
+		 * For file in ICB data is stored in allocation descriptor
+		 * so sizes should match
+		 */
+		if (iinfo->i_lenAlloc != inode->i_size)
+			goto out;
+		/* File in ICB has to fit in there... */
+		if (inode->i_size > inode->i_sb->s_blocksize -
+					udf_file_entry_alloc_offset(inode))
+			goto out;
+	}
 
 	switch (fe->icbTag.fileType) {
 	case ICBTAG_FILE_TYPE_DIRECTORY:
```
