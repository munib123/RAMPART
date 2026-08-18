# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1694_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1694_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 5742-5782 of the vulnerable file.

	info.active_disks  = insync;
	info.working_disks = working;
	info.failed_disks  = failed;
	info.spare_disks   = spare;

	info.layout        = mddev->layout;
	info.chunk_size    = mddev->chunk_sectors << 9;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static int get_bitmap_file(struct mddev *mddev, void __user * arg)
{
	mdu_bitmap_file_t *file = NULL; /* too big for stack allocation */
	char *ptr;
	int err;

	file = kmalloc(sizeof(*file), GFP_NOIO);
	if (!file)
		return -ENOMEM;

	err = 0;
	spin_lock(&mddev->lock);
	/* bitmap disabled, zero the first byte and copy out */
	if (!mddev->bitmap_info.file)
		file->pathname[0] = '\0';
	else if ((ptr = file_path(mddev->bitmap_info.file,
			       file->pathname, sizeof(file->pathname))),
		 IS_ERR(ptr))
		err = PTR_ERR(ptr);
	else
		memmove(file->pathname, ptr,
			sizeof(file->pathname)-(ptr-file->pathname));
	spin_unlock(&mddev->lock);

	if (err == 0 &&
	    copy_to_user(arg, file, sizeof(*file)))
		err = -EFAULT;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5759,7 +5759,7 @@
 	char *ptr;
 	int err;
 
-	file = kmalloc(sizeof(*file), GFP_NOIO);
+	file = kzalloc(sizeof(*file), GFP_NOIO);
 	if (!file)
 		return -ENOMEM;
 
```
