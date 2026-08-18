# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2527_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2527_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1942-1982 of the vulnerable file.

}

static int snd_timer_user_fasync(int fd, struct file * file, int on)
{
	struct snd_timer_user *tu;

	tu = file->private_data;
	return fasync_helper(fd, file, on, &tu->fasync);
}

static ssize_t snd_timer_user_read(struct file *file, char __user *buffer,
				   size_t count, loff_t *offset)
{
	struct snd_timer_user *tu;
	long result = 0, unit;
	int qhead;
	int err = 0;

	tu = file->private_data;
	unit = tu->tread ? sizeof(struct snd_timer_tread) : sizeof(struct snd_timer_read);
	spin_lock_irq(&tu->qlock);
	while ((long)count - result >= unit) {
		while (!tu->qused) {
			wait_queue_t wait;

			if ((file->f_flags & O_NONBLOCK) != 0 || result > 0) {
				err = -EAGAIN;
				goto _error;
			}

			set_current_state(TASK_INTERRUPTIBLE);
			init_waitqueue_entry(&wait, current);
			add_wait_queue(&tu->qchange_sleep, &wait);

			spin_unlock_irq(&tu->qlock);
			schedule();
			spin_lock_irq(&tu->qlock);

			remove_wait_queue(&tu->qchange_sleep, &wait);

			if (tu->disconnected) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1959,6 +1959,7 @@
 
 	tu = file->private_data;
 	unit = tu->tread ? sizeof(struct snd_timer_tread) : sizeof(struct snd_timer_read);
+	mutex_lock(&tu->ioctl_lock);
 	spin_lock_irq(&tu->qlock);
 	while ((long)count - result >= unit) {
 		while (!tu->qused) {
@@ -1974,7 +1975,9 @@
 			add_wait_queue(&tu->qchange_sleep, &wait);
 
 			spin_unlock_irq(&tu->qlock);
+			mutex_unlock(&tu->ioctl_lock);
 			schedule();
+			mutex_lock(&tu->ioctl_lock);
 			spin_lock_irq(&tu->qlock);
 
 			remove_wait_queue(&tu->qchange_sleep, &wait);
@@ -1994,7 +1997,6 @@
 		tu->qused--;
 		spin_unlock_irq(&tu->qlock);
 
-		mutex_lock(&tu->ioctl_lock);
 		if (tu->tread) {
 			if (copy_to_user(buffer, &tu->tqueue[qhead],
 					 sizeof(struct snd_timer_tread)))
@@ -2004,7 +2006,6 @@
 					 sizeof(struct snd_timer_read)))
 				err = -EFAULT;
 		}
-		mutex_unlock(&tu->ioctl_lock);
 
 		spin_lock_irq(&tu->qlock);
 		if (err < 0)
@@ -2014,6 +2015,7 @@
 	}
  _error:
 	spin_unlock_irq(&tu->qlock);
+	mutex_unlock(&tu->ioctl_lock);
 	return result > 0 ? result : err;
 }
 
```
