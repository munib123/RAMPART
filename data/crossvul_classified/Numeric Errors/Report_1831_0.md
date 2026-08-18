# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 1831_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1831_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 188-228 of the vulnerable file.

{
    unsigned char *data = NULL;
    int size;
    loff_t offs;

    if (new == -1)
	new = FAT_EOF(fs);
    else if ((long)new == -2)
	new = FAT_BAD(fs);
    switch (fs->fat_bits) {
    case 12:
	data = fs->fat + cluster * 3 / 2;
	offs = fs->fat_start + cluster * 3 / 2;
	if (cluster & 1) {
	    FAT_ENTRY prevEntry;
	    get_fat(&prevEntry, fs->fat, cluster - 1, fs);
	    data[0] = ((new & 0xf) << 4) | (prevEntry.value >> 8);
	    data[1] = new >> 4;
	} else {
	    FAT_ENTRY subseqEntry;
	    if (cluster != fs->clusters - 1)
		get_fat(&subseqEntry, fs->fat, cluster + 1, fs);
	    else
		subseqEntry.value = 0;
	    data[0] = new & 0xff;
	    data[1] = (new >> 8) | ((0xff & subseqEntry.value) << 4);
	}
	size = 2;
	break;
    case 16:
	data = fs->fat + cluster * 2;
	offs = fs->fat_start + cluster * 2;
	*(unsigned short *)data = htole16(new);
	size = 2;
	break;
    case 32:
	{
	    FAT_ENTRY curEntry;
	    get_fat(&curEntry, fs->fat, cluster, fs);

	    data = fs->fat + cluster * 4;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -205,7 +205,7 @@
 	    data[1] = new >> 4;
 	} else {
 	    FAT_ENTRY subseqEntry;
-	    if (cluster != fs->clusters - 1)
+	    if (cluster != fs->clusters + 1)
 		get_fat(&subseqEntry, fs->fat, cluster + 1, fs);
 	    else
 		subseqEntry.value = 0;
```
