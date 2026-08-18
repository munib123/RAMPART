# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 4963_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4963_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 56-96 of the vulnerable file.

MODULE_ALIAS_CHARDEV(CONFIG_SND_MAJOR, SNDRV_MINOR_TIMER);
MODULE_ALIAS("devname:snd/timer");

struct snd_timer_user {
	struct snd_timer_instance *timeri;
	int tread;		/* enhanced read with timestamps and events */
	unsigned long ticks;
	unsigned long overrun;
	int qhead;
	int qtail;
	int qused;
	int queue_size;
	struct snd_timer_read *queue;
	struct snd_timer_tread *tqueue;
	spinlock_t qlock;
	unsigned long last_resolution;
	unsigned int filter;
	struct timespec tstamp;		/* trigger tstamp */
	wait_queue_head_t qchange_sleep;
	struct fasync_struct *fasync;
	struct mutex tread_sem;
};

/* list of timers */
static LIST_HEAD(snd_timer_list);

/* list of slave instances */
static LIST_HEAD(snd_timer_slave_list);

/* lock for slave active lists */
static DEFINE_SPINLOCK(slave_active_lock);

static DEFINE_MUTEX(register_mutex);

static int snd_timer_free(struct snd_timer *timer);
static int snd_timer_dev_free(struct snd_device *device);
static int snd_timer_dev_register(struct snd_device *device);
static int snd_timer_dev_disconnect(struct snd_device *device);

static void snd_timer_reschedule(struct snd_timer * timer, unsigned long ticks_left);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,7 +73,7 @@
 	struct timespec tstamp;		/* trigger tstamp */
 	wait_queue_head_t qchange_sleep;
 	struct fasync_struct *fasync;
-	struct mutex tread_sem;
+	struct mutex ioctl_lock;
 };
 
 /* list of timers */
@@ -1253,7 +1253,7 @@
 		return -ENOMEM;
 	spin_lock_init(&tu->qlock);
 	init_waitqueue_head(&tu->qchange_sleep);
-	mutex_init(&tu->tread_sem);
+	mutex_init(&tu->ioctl_lock);
 	tu->ticks = 1;
 	tu->queue_size = 128;
 	tu->queue = kmalloc(tu->queue_size * sizeof(struct snd_timer_read),
@@ -1273,8 +1273,10 @@
 	if (file->private_data) {
 		tu = file->private_data;
 		file->private_data = NULL;
+		mutex_lock(&tu->ioctl_lock);
 		if (tu->timeri)
 			snd_timer_close(tu->timeri);
+		mutex_unlock(&tu->ioctl_lock);
 		kfree(tu->queue);
 		kfree(tu->tqueue);
 		kfree(tu);
@@ -1512,7 +1514,6 @@
 	int err = 0;
 
 	tu = file->private_data;
-	mutex_lock(&tu->tread_sem);
 	if (tu->timeri) {
 		snd_timer_close(tu->timeri);
 		tu->timeri = NULL;
@@ -1556,7 +1557,6 @@
 	}
 
       __err:
-      	mutex_unlock(&tu->tread_sem);
 	return err;
 }
 
@@ -1769,7 +1769,7 @@
 	SNDRV_TIMER_IOCTL_PAUSE_OLD = _IO('T', 0x23),
 };
 
-static long snd_timer_user_ioctl(struct file *file, unsigned int cmd,
+static long __snd_timer_user_ioctl(struct file *file, unsigned int cmd,
 				 unsigned long arg)
 {
 	struct snd_timer_user *tu;
@@ -1786,17 +1786,11 @@
 	{
 		int xarg;
 
-		mutex_lock(&tu->tread_sem);
-		if (tu->timeri)	{	/* too late */
-			mutex_unlock(&tu->tread_sem);
+		if (tu->timeri)	/* too late */
 			return -EBUSY;
-		}
-		if (get_user(xarg, p)) {
-			mutex_unlock(&tu->tread_sem);
+		if (get_user(xarg, p))
 			return -EFAULT;
-		}
 		tu->tread = xarg ? 1 : 0;
-		mutex_unlock(&tu->tread_sem);
 		return 0;
 	}
 	case SNDRV_TIMER_IOCTL_GINFO:
@@ -1829,6 +1823,18 @@
 	return -ENOTTY;
 }
 
+static long snd_timer_user_ioctl(struct file *file, unsigned int cmd,
+				 unsigned long arg)
+{
+	struct snd_timer_user *tu = file->private_data;
+	long ret;
+
+	mutex_lock(&tu->ioctl_lock);
+	ret = __snd_timer_user_ioctl(file, cmd, arg);
+	mutex_unlock(&tu->ioctl_lock);
+	return ret;
+}
+
 static int snd_timer_user_fasync(int fd, struct file * file, int on)
 {
 	struct snd_timer_user *tu;
```
