# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3449_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3449_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 273-313 of the vulnerable file.


		schedule();
	}

	finish_wait(&group->notification_waitq, &wait);
	if (start != buf && ret != -EFAULT)
		ret = buf - start;
	return ret;
}

static int inotify_fasync(int fd, struct file *file, int on)
{
	struct fsnotify_group *group = file->private_data;

	return fasync_helper(fd, file, on, &group->inotify_data.fa) >= 0 ? 0 : -EIO;
}

static int inotify_release(struct inode *ignored, struct file *file)
{
	struct fsnotify_group *group = file->private_data;
	struct user_struct *user = group->inotify_data.user;

	pr_debug("%s: group=%p\n", __func__, group);

	fsnotify_clear_marks_by_group(group);

	/* free this group, matching get was inotify_init->fsnotify_obtain_group */
	fsnotify_put_group(group);

	atomic_dec(&user->inotify_devs);

	return 0;
}

static long inotify_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct fsnotify_group *group;
	struct fsnotify_event_holder *holder;
	struct fsnotify_event *event;
	void __user *p;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -290,7 +290,6 @@
 static int inotify_release(struct inode *ignored, struct file *file)
 {
 	struct fsnotify_group *group = file->private_data;
-	struct user_struct *user = group->inotify_data.user;
 
 	pr_debug("%s: group=%p\n", __func__, group);
 
@@ -298,8 +297,6 @@
 
 	/* free this group, matching get was inotify_init->fsnotify_obtain_group */
 	fsnotify_put_group(group);
-
-	atomic_dec(&user->inotify_devs);
 
 	return 0;
 }
@@ -697,7 +694,7 @@
 	return ret;
 }
 
-static struct fsnotify_group *inotify_new_group(struct user_struct *user, unsigned int max_events)
+static struct fsnotify_group *inotify_new_group(unsigned int max_events)
 {
 	struct fsnotify_group *group;
 
@@ -710,8 +707,14 @@
 	spin_lock_init(&group->inotify_data.idr_lock);
 	idr_init(&group->inotify_data.idr);
 	group->inotify_data.last_wd = 0;
-	group->inotify_data.user = user;
 	group->inotify_data.fa = NULL;
+	group->inotify_data.user = get_current_user();
+
+	if (atomic_inc_return(&group->inotify_data.user->inotify_devs) >
+	    inotify_max_user_instances) {
+		fsnotify_put_group(group);
+		return ERR_PTR(-EMFILE);
+	}
 
 	return group;
 }
@@ -721,7 +724,6 @@
 SYSCALL_DEFINE1(inotify_init1, int, flags)
 {
 	struct fsnotify_group *group;
-	struct user_struct *user;
 	int ret;
 
 	/* Check the IN_* constants for consistency.  */
@@ -731,31 +733,16 @@
 	if (flags & ~(IN_CLOEXEC | IN_NONBLOCK))
 		return -EINVAL;
 
-	user = get_current_user();
-	if (unlikely(atomic_read(&user->inotify_devs) >=
-			inotify_max_user_instances)) {
-		ret = -EMFILE;
-		goto out_free_uid;
-	}
-
 	/* fsnotify_obtain_group took a reference to group, we put this when we kill the file in the end */
-	group = inotify_new_group(user, inotify_max_queued_events);
-	if (IS_ERR(group)) {
-		ret = PTR_ERR(group);
-		goto out_free_uid;
-	}
-
-	atomic_inc(&user->inotify_devs);
+	group = inotify_new_group(inotify_max_queued_events);
+	if (IS_ERR(group))
+		return PTR_ERR(group);
 
 	ret = anon_inode_getfd("inotify", &inotify_fops, group,
 				  O_RDONLY | flags);
-	if (ret >= 0)
-		return ret;
-
-	fsnotify_put_group(group);
-	atomic_dec(&user->inotify_devs);
-out_free_uid:
-	free_uid(user);
+	if (ret < 0)
+		fsnotify_put_group(group);
+
 	return ret;
 }
 
```
