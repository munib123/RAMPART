# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 1624_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1624_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1470-1510 of the vulnerable file.

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

	/* Sanity checks for files in ICB so that we don't get confused later */
	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
		/*
		 * For file in ICB data is stored in allocation descriptor
		 * so sizes should match
		 */
		if (iinfo->i_lenAlloc != inode->i_size)
			goto out;
		/* File in ICB has to fit in there... */
		if (inode->i_size > bs - udf_file_entry_alloc_offset(inode))
			goto out;
	}

	switch (fe->icbTag.fileType) {
	case ICBTAG_FILE_TYPE_DIRECTORY:
		inode->i_op = &udf_dir_inode_operations;
		inode->i_fop = &udf_dir_operations;
		inode->i_mode |= S_IFDIR;
		inc_nlink(inode);
		break;
	case ICBTAG_FILE_TYPE_REALTIME:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1487,6 +1487,15 @@
 	}
 	inode->i_generation = iinfo->i_unique;
 
+	/*
+	 * Sanity check length of allocation descriptors and extended attrs to
+	 * avoid integer overflows
+	 */
+	if (iinfo->i_lenEAttr > bs || iinfo->i_lenAlloc > bs)
+		goto out;
+	/* Now do exact checks */
+	if (udf_file_entry_alloc_offset(inode) + iinfo->i_lenAlloc > bs)
+		goto out;
 	/* Sanity checks for files in ICB so that we don't get confused later */
 	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
 		/*
```
