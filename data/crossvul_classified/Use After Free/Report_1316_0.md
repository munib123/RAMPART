# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1316_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1316_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 267-307 of the vulnerable file.

			timeri = NULL;
		}
		goto unlock;
	}

	/* open a master instance */
	timer = snd_timer_find(tid);
#ifdef CONFIG_MODULES
	if (!timer) {
		mutex_unlock(&register_mutex);
		snd_timer_request(tid);
		mutex_lock(&register_mutex);
		timer = snd_timer_find(tid);
	}
#endif
	if (!timer) {
		err = -ENODEV;
		goto unlock;
	}
	if (!list_empty(&timer->open_list_head)) {
		timeri = list_entry(timer->open_list_head.next,
				    struct snd_timer_instance, open_list);
		if (timeri->flags & SNDRV_TIMER_IFLG_EXCLUSIVE) {
			err = -EBUSY;
			timeri = NULL;
			goto unlock;
		}
	}
	if (timer->num_instances >= timer->max_instances) {
		err = -EBUSY;
		goto unlock;
	}
	timeri = snd_timer_instance_new(owner, timer);
	if (!timeri) {
		err = -ENOMEM;
		goto unlock;
	}
	/* take a card refcount for safe disconnection */
	if (timer->card)
		get_device(&timer->card->card_dev);
	timeri->slave_class = tid->dev_sclass;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -284,11 +284,11 @@
 		goto unlock;
 	}
 	if (!list_empty(&timer->open_list_head)) {
-		timeri = list_entry(timer->open_list_head.next,
+		struct snd_timer_instance *t =
+			list_entry(timer->open_list_head.next,
 				    struct snd_timer_instance, open_list);
-		if (timeri->flags & SNDRV_TIMER_IFLG_EXCLUSIVE) {
+		if (t->flags & SNDRV_TIMER_IFLG_EXCLUSIVE) {
 			err = -EBUSY;
-			timeri = NULL;
 			goto unlock;
 		}
 	}
```
