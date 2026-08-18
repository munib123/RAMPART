# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4965_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4965_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 73-113 of the vulnerable file.

	return 0;
}

static int snd_hrtimer_close(struct snd_timer *t)
{
	struct snd_hrtimer *stime = t->private_data;

	if (stime) {
		hrtimer_cancel(&stime->hrt);
		kfree(stime);
		t->private_data = NULL;
	}
	return 0;
}

static int snd_hrtimer_start(struct snd_timer *t)
{
	struct snd_hrtimer *stime = t->private_data;

	atomic_set(&stime->running, 0);
	hrtimer_cancel(&stime->hrt);
	hrtimer_start(&stime->hrt, ns_to_ktime(t->sticks * resolution),
		      HRTIMER_MODE_REL);
	atomic_set(&stime->running, 1);
	return 0;
}

static int snd_hrtimer_stop(struct snd_timer *t)
{
	struct snd_hrtimer *stime = t->private_data;
	atomic_set(&stime->running, 0);
	return 0;
}

static struct snd_timer_hardware hrtimer_hw = {
	.flags =	SNDRV_TIMER_HW_AUTO | SNDRV_TIMER_HW_TASKLET,
	.open =		snd_hrtimer_open,
	.close =	snd_hrtimer_close,
	.start =	snd_hrtimer_start,
	.stop =		snd_hrtimer_stop,
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,7 +90,7 @@
 	struct snd_hrtimer *stime = t->private_data;
 
 	atomic_set(&stime->running, 0);
-	hrtimer_cancel(&stime->hrt);
+	hrtimer_try_to_cancel(&stime->hrt);
 	hrtimer_start(&stime->hrt, ns_to_ktime(t->sticks * resolution),
 		      HRTIMER_MODE_REL);
 	atomic_set(&stime->running, 1);
@@ -101,6 +101,7 @@
 {
 	struct snd_hrtimer *stime = t->private_data;
 	atomic_set(&stime->running, 0);
+	hrtimer_try_to_cancel(&stime->hrt);
 	return 0;
 }
 
```
