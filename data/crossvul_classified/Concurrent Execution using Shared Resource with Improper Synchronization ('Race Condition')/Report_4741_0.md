# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 4741_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4741_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 2642-2682 of the vulnerable file.

 *
 *	Set the line discipline according to user request.
 *
 *	Locking: see tty_set_ldisc, this function is just a helper
 */

static int tiocsetd(struct tty_struct *tty, int __user *p)
{
	int ldisc;
	int ret;

	if (get_user(ldisc, p))
		return -EFAULT;

	ret = tty_set_ldisc(tty, ldisc);

	return ret;
}

/**
 *	send_break	-	performed time break
 *	@tty: device to break on
 *	@duration: timeout in mS
 *
 *	Perform a timed break on hardware that lacks its own driver level
 *	timed break functionality.
 *
 *	Locking:
 *		atomic_write_lock serializes
 *
 */

static int send_break(struct tty_struct *tty, unsigned int duration)
{
	int retval;

	if (tty->ops->break_ctl == NULL)
		return 0;

	if (tty->driver->flags & TTY_DRIVER_HARDWARE_BREAK)
		retval = tty->ops->break_ctl(tty, duration);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2659,6 +2659,28 @@
 }
 
 /**
+ *	tiocgetd	-	get line discipline
+ *	@tty: tty device
+ *	@p: pointer to user data
+ *
+ *	Retrieves the line discipline id directly from the ldisc.
+ *
+ *	Locking: waits for ldisc reference (in case the line discipline
+ *		is changing or the tty is being hungup)
+ */
+
+static int tiocgetd(struct tty_struct *tty, int __user *p)
+{
+	struct tty_ldisc *ld;
+	int ret;
+
+	ld = tty_ldisc_ref_wait(tty);
+	ret = put_user(ld->ops->num, p);
+	tty_ldisc_deref(ld);
+	return ret;
+}
+
+/**
  *	send_break	-	performed time break
  *	@tty: device to break on
  *	@duration: timeout in mS
@@ -2884,7 +2906,7 @@
 	case TIOCGSID:
 		return tiocgsid(tty, real_tty, p);
 	case TIOCGETD:
-		return put_user(tty->ldisc->ops->num, (int __user *)p);
+		return tiocgetd(tty, p);
 	case TIOCSETD:
 		return tiocsetd(tty, p);
 	case TIOCVHANGUP:
```
