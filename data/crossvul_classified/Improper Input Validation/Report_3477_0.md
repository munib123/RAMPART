# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3477_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3477_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 121-161 of the vulnerable file.

	} else if (!strcmp(type, TOMOYO_MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
		   !strcmp(type, TOMOYO_MOUNT_MAKE_PRIVATE_KEYWORD) ||
		   !strcmp(type, TOMOYO_MOUNT_MAKE_SLAVE_KEYWORD) ||
		   !strcmp(type, TOMOYO_MOUNT_MAKE_SHARED_KEYWORD)) {
		/* dev_name is ignored. */
	} else if (!strcmp(type, TOMOYO_MOUNT_BIND_KEYWORD) ||
		   !strcmp(type, TOMOYO_MOUNT_MOVE_KEYWORD)) {
		need_dev = -1; /* dev_name is a directory */
	} else {
		fstype = get_fs_type(type);
		if (!fstype) {
			error = -ENODEV;
			goto out;
		}
		if (fstype->fs_flags & FS_REQUIRES_DEV)
			/* dev_name is a block device file. */
			need_dev = 1;
	}
	if (need_dev) {
		/* Get mount point or device file. */
		if (kern_path(dev_name, LOOKUP_FOLLOW, &path)) {
			error = -ENOENT;
			goto out;
		}
		requested_dev_name = tomoyo_realpath_from_path(&path);
		path_put(&path);
		if (!requested_dev_name) {
			error = -ENOENT;
			goto out;
		}
	} else {
		/* Map dev_name to "<NULL>" if no dev_name given. */
		if (!dev_name)
			dev_name = "<NULL>";
		requested_dev_name = tomoyo_encode(dev_name);
		if (!requested_dev_name) {
			error = -ENOMEM;
			goto out;
		}
	}
	rdev.name = requested_dev_name;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -138,7 +138,7 @@
 	}
 	if (need_dev) {
 		/* Get mount point or device file. */
-		if (kern_path(dev_name, LOOKUP_FOLLOW, &path)) {
+		if (!dev_name || kern_path(dev_name, LOOKUP_FOLLOW, &path)) {
 			error = -ENOENT;
 			goto out;
 		}
```
