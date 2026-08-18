# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4966_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4966_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 70-110 of the vulnerable file.

	struct scm_fp_list *fpl = *fplp;
	struct file **fpp;
	int i, num;

	num = (cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr)))/sizeof(int);

	if (num <= 0)
		return 0;

	if (num > SCM_MAX_FD)
		return -EINVAL;

	if (!fpl)
	{
		fpl = kmalloc(sizeof(struct scm_fp_list), GFP_KERNEL);
		if (!fpl)
			return -ENOMEM;
		*fplp = fpl;
		fpl->count = 0;
		fpl->max = SCM_MAX_FD;
	}
	fpp = &fpl->fp[fpl->count];

	if (fpl->count + num > fpl->max)
		return -EINVAL;

	/*
	 *	Verify the descriptors and increment the usage count.
	 */

	for (i=0; i< num; i++)
	{
		int fd = fdp[i];
		struct file *file;

		if (fd < 0 || !(file = fget_raw(fd)))
			return -EBADF;
		*fpp++ = file;
		fpl->count++;
	}
	return num;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,6 +87,7 @@
 		*fplp = fpl;
 		fpl->count = 0;
 		fpl->max = SCM_MAX_FD;
+		fpl->user = NULL;
 	}
 	fpp = &fpl->fp[fpl->count];
 
@@ -107,6 +108,10 @@
 		*fpp++ = file;
 		fpl->count++;
 	}
+
+	if (!fpl->user)
+		fpl->user = get_uid(current_user());
+
 	return num;
 }
 
@@ -119,6 +124,7 @@
 		scm->fp = NULL;
 		for (i=fpl->count-1; i>=0; i--)
 			fput(fpl->fp[i]);
+		free_uid(fpl->user);
 		kfree(fpl);
 	}
 }
@@ -336,6 +342,7 @@
 		for (i = 0; i < fpl->count; i++)
 			get_file(fpl->fp[i]);
 		new_fpl->max = new_fpl->count;
+		new_fpl->user = get_uid(fpl->user);
 	}
 	return new_fpl;
 }
```
