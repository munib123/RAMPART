# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 3866_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3866_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 2422-2462 of the vulnerable file.

/**
* Print details on a specific file to a file handle.
*
* @param fs File system file is located in
* @param hFile File handle to print text to
* @param inum Address of file in file system
* @param numblock The number of blocks in file to force print (can go beyond file size)
* @param sec_skew Clock skew in seconds to also print times in
*
* @returns 1 on error and 0 on success
*/
static uint8_t
    yaffsfs_istat(TSK_FS_INFO *fs, TSK_FS_ISTAT_FLAG_ENUM flags, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    TSK_FS_META *fs_meta;
    TSK_FS_FILE *fs_file;
    YAFFSFS_INFO *yfs = (YAFFSFS_INFO *)fs;
    char ls[12];
    YAFFSFS_PRINT_ADDR print;
    char timeBuf[32];
    YaffsCacheObject * obj = NULL;
    YaffsCacheVersion * version = NULL;
    YaffsHeader * header = NULL;

    yaffscache_version_find_by_inode(yfs, inum, &version, &obj);

    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
        return 1;
    }
    fs_meta = fs_file->meta;

    tsk_fprintf(hFile, "inode: %" PRIuINUM "\n", inum);
    tsk_fprintf(hFile, "%sAllocated\n",
        (fs_meta->flags & TSK_FS_META_FLAG_ALLOC) ? "" : "Not ");

    if (fs_meta->link)
        tsk_fprintf(hFile, "symbolic link to: %s\n", fs_meta->link);

    tsk_fprintf(hFile, "uid / gid: %" PRIuUID " / %" PRIuGID "\n",
        fs_meta->uid, fs_meta->gid);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2439,7 +2439,7 @@
     YAFFSFS_INFO *yfs = (YAFFSFS_INFO *)fs;
     char ls[12];
     YAFFSFS_PRINT_ADDR print;
-    char timeBuf[32];
+    char timeBuf[128];
     YaffsCacheObject * obj = NULL;
     YaffsCacheVersion * version = NULL;
     YaffsHeader * header = NULL;
```
