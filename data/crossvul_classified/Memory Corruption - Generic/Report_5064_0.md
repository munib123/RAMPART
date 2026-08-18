# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5064_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5064_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 86-127 of the vulnerable file.

	char id[9];
	strncpy(id, (const char *)b->system_id, 8);
	id[8] = 0;
	printf("System ID \"%s\"\n", id);
    } else {
	/* On Atari, a 24 bit serial number is stored at offset 8 of the boot
	 * sector */
	printf("Serial number 0x%x\n",
	       b->system_id[5] | (b->system_id[6] << 8) | (b->
							   system_id[7] << 16));
    }
    printf("Media byte 0x%02x (%s)\n", b->media, get_media_descr(b->media));
    printf("%10d bytes per logical sector\n", GET_UNALIGNED_W(b->sector_size));
    printf("%10d bytes per cluster\n", fs->cluster_size);
    printf("%10d reserved sector%s\n", le16toh(b->reserved),
	   le16toh(b->reserved) == 1 ? "" : "s");
    printf("First FAT starts at byte %llu (sector %llu)\n",
	   (unsigned long long)fs->fat_start,
	   (unsigned long long)fs->fat_start / lss);
    printf("%10d FATs, %d bit entries\n", b->fats, fs->fat_bits);
    printf("%10d bytes per FAT (= %u sectors)\n", fs->fat_size,
	   fs->fat_size / lss);
    if (!fs->root_cluster) {
	printf("Root directory starts at byte %llu (sector %llu)\n",
	       (unsigned long long)fs->root_start,
	       (unsigned long long)fs->root_start / lss);
	printf("%10d root directory entries\n", fs->root_entries);
    } else {
	printf("Root directory start at cluster %lu (arbitrary size)\n",
	       (unsigned long)fs->root_cluster);
    }
    printf("Data area starts at byte %llu (sector %llu)\n",
	   (unsigned long long)fs->data_start,
	   (unsigned long long)fs->data_start / lss);
    printf("%10lu data clusters (%llu bytes)\n",
	   (unsigned long)fs->data_clusters,
	   (unsigned long long)fs->data_clusters * fs->cluster_size);
    printf("%u sectors/track, %u heads\n", le16toh(b->secs_track),
	   le16toh(b->heads));
    printf("%10u hidden sectors\n", atari_format ?
	   /* On Atari, the hidden field is only 16 bit wide and unused */
	   (((unsigned char *)&b->hidden)[0] |
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,8 +103,8 @@
 	   (unsigned long long)fs->fat_start,
 	   (unsigned long long)fs->fat_start / lss);
     printf("%10d FATs, %d bit entries\n", b->fats, fs->fat_bits);
-    printf("%10d bytes per FAT (= %u sectors)\n", fs->fat_size,
-	   fs->fat_size / lss);
+    printf("%10lld bytes per FAT (= %llu sectors)\n", (long long)fs->fat_size,
+	   (long long)fs->fat_size / lss);
     if (!fs->root_cluster) {
 	printf("Root directory starts at byte %llu (sector %llu)\n",
 	       (unsigned long long)fs->root_start,
@@ -329,7 +329,7 @@
     struct boot_sector b;
     unsigned total_sectors;
     unsigned short logical_sector_size, sectors;
-    unsigned fat_length;
+    off_t fat_length;
     unsigned total_fat_entries;
     off_t data_size;
 
@@ -358,8 +358,12 @@
     /* Can't access last odd sector anyway, so round down */
     fs_test((off_t)((total_sectors & ~1) - 1) * logical_sector_size,
 	    logical_sector_size);
+
     fat_length = le16toh(b.fat_length) ?
 	le16toh(b.fat_length) : le32toh(b.fat32_length);
+    if (!fat_length)
+	die("FAT size is zero.");
+
     fs->fat_start = (off_t)le16toh(b.reserved) * logical_sector_size;
     fs->root_start = ((off_t)le16toh(b.reserved) + b.fats * fat_length) *
 	logical_sector_size;
@@ -367,7 +371,11 @@
     fs->data_start = fs->root_start + ROUND_TO_MULTIPLE(fs->root_entries <<
 							MSDOS_DIR_BITS,
 							logical_sector_size);
+
     data_size = (off_t)total_sectors * logical_sector_size - fs->data_start;
+    if (data_size < fs->cluster_size)
+	die("Filesystem has no space for any data clusters");
+
     fs->data_clusters = data_size / fs->cluster_size;
     fs->root_cluster = 0;	/* indicates standard, pre-FAT32 root dir */
     fs->fsinfo_start = 0;	/* no FSINFO structure */
```
