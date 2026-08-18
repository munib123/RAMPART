# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1773_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1773_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 189-229 of the vulnerable file.

		exfat_close(ef->dev);
		exfat_error("failed to allocate memory for the super block");
		return -ENOMEM;
	}
	memset(ef->sb, 0, sizeof(struct exfat_super_block));

	if (exfat_pread(ef->dev, ef->sb, sizeof(struct exfat_super_block), 0) < 0)
	{
		exfat_close(ef->dev);
		free(ef->sb);
		exfat_error("failed to read boot sector");
		return -EIO;
	}
	if (memcmp(ef->sb->oem_name, "EXFAT   ", 8) != 0)
	{
		exfat_close(ef->dev);
		free(ef->sb);
		exfat_error("exFAT file system is not found");
		return -EIO;
	}
	ef->zero_cluster = malloc(CLUSTER_SIZE(*ef->sb));
	if (ef->zero_cluster == NULL)
	{
		exfat_close(ef->dev);
		free(ef->sb);
		exfat_error("failed to allocate zero sector");
		return -ENOMEM;
	}
	/* use zero_cluster as a temporary buffer for VBR checksum verification */
	if (!verify_vbr_checksum(ef->dev, ef->zero_cluster, SECTOR_SIZE(*ef->sb)))
	{
		free(ef->zero_cluster);
		exfat_close(ef->dev);
		free(ef->sb);
		return -EIO;
	}
	memset(ef->zero_cluster, 0, CLUSTER_SIZE(*ef->sb));
	if (ef->sb->version.major != 1 || ef->sb->version.minor != 0)
	{
		free(ef->zero_cluster);
		exfat_close(ef->dev);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -206,6 +206,23 @@
 		exfat_error("exFAT file system is not found");
 		return -EIO;
 	}
+	/* sector cannot be smaller than 512 bytes */
+	if (ef->sb->sector_bits < 9)
+	{
+		exfat_close(ef->dev);
+		exfat_error("too small sector size: 2^%hhd", ef->sb->sector_bits);
+		free(ef->sb);
+		return -EIO;
+	}
+	/* officially exFAT supports cluster size up to 32 MB */
+	if ((int) ef->sb->sector_bits + (int) ef->sb->spc_bits > 25)
+	{
+		exfat_close(ef->dev);
+		exfat_error("too big cluster size: 2^(%hhd+%hhd)",
+				ef->sb->sector_bits, ef->sb->spc_bits);
+		free(ef->sb);
+		return -EIO;
+	}
 	ef->zero_cluster = malloc(CLUSTER_SIZE(*ef->sb));
 	if (ef->zero_cluster == NULL)
 	{
@@ -237,16 +254,6 @@
 		free(ef->zero_cluster);
 		exfat_close(ef->dev);
 		exfat_error("unsupported FAT count: %hhu", ef->sb->fat_count);
-		free(ef->sb);
-		return -EIO;
-	}
-	/* officially exFAT supports cluster size up to 32 MB */
-	if ((int) ef->sb->sector_bits + (int) ef->sb->spc_bits > 25)
-	{
-		free(ef->zero_cluster);
-		exfat_close(ef->dev);
-		exfat_error("too big cluster size: 2^%d",
-				(int) ef->sb->sector_bits + (int) ef->sb->spc_bits);
 		free(ef->sb);
 		return -EIO;
 	}
```
