# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3411_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3411_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 270-310 of the vulnerable file.

   blocks have a size of LOG2BLOCKSIZE (in log2).  */
grub_ssize_t
grub_fshelp_read_file (grub_disk_t disk, grub_fshelp_node_t node,
		       void (*read_hook) (grub_disk_addr_t sector,
					  unsigned offset,
					  unsigned length,
					  void *closure),
		       void *closure, int flags,
		       grub_off_t pos, grub_size_t len, char *buf,
		       grub_disk_addr_t (*get_block) (grub_fshelp_node_t node,
						      grub_disk_addr_t block),
		       grub_off_t filesize, int log2blocksize)
{
  grub_disk_addr_t i, blockcnt;
  int blocksize = 1 << (log2blocksize + GRUB_DISK_SECTOR_BITS);

  /* Adjust LEN so it we can't read past the end of the file.  */
  if (pos + len > filesize)
    len = filesize - pos;

  blockcnt = ((len + pos) + blocksize - 1) >>
    (log2blocksize + GRUB_DISK_SECTOR_BITS);

  for (i = pos >> (log2blocksize + GRUB_DISK_SECTOR_BITS); i < blockcnt; i++)
    {
      grub_disk_addr_t blknr;
      int blockoff = pos & (blocksize - 1);
      int blockend = blocksize;

      int skipfirst = 0;

      blknr = get_block (node, i);
      if (grub_errno)
	return -1;

      blknr = blknr << log2blocksize;

      /* Last block.  */
      if (i == blockcnt - 1)
	{
	  blockend = (len + pos) & (blocksize - 1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -287,6 +287,10 @@
   if (pos + len > filesize)
     len = filesize - pos;
 
+  if (len < 1 || len == 0xffffffff) {
+    return -1;
+  }
+
   blockcnt = ((len + pos) + blocksize - 1) >>
     (log2blocksize + GRUB_DISK_SECTOR_BITS);
 
```
