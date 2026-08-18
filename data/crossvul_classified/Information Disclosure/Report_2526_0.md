# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2526_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2526_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1601-1641 of the vulnerable file.

	struct snd_timer_select tselect;
	char str[32];
	int err = 0;

	tu = file->private_data;
	if (tu->timeri) {
		snd_timer_close(tu->timeri);
		tu->timeri = NULL;
	}
	if (copy_from_user(&tselect, _tselect, sizeof(tselect))) {
		err = -EFAULT;
		goto __err;
	}
	sprintf(str, "application %i", current->pid);
	if (tselect.id.dev_class != SNDRV_TIMER_CLASS_SLAVE)
		tselect.id.dev_sclass = SNDRV_TIMER_SCLASS_APPLICATION;
	err = snd_timer_open(&tu->timeri, str, &tselect.id, current->pid);
	if (err < 0)
		goto __err;

	kfree(tu->queue);
	tu->queue = NULL;
	kfree(tu->tqueue);
	tu->tqueue = NULL;
	if (tu->tread) {
		tu->tqueue = kmalloc(tu->queue_size * sizeof(struct snd_timer_tread),
				     GFP_KERNEL);
		if (tu->tqueue == NULL)
			err = -ENOMEM;
	} else {
		tu->queue = kmalloc(tu->queue_size * sizeof(struct snd_timer_read),
				    GFP_KERNEL);
		if (tu->queue == NULL)
			err = -ENOMEM;
	}

      	if (err < 0) {
		snd_timer_close(tu->timeri);
      		tu->timeri = NULL;
      	} else {
		tu->timeri->flags |= SNDRV_TIMER_IFLG_FAST;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1618,6 +1618,7 @@
 	if (err < 0)
 		goto __err;
 
+	tu->qhead = tu->qtail = tu->qused = 0;
 	kfree(tu->queue);
 	tu->queue = NULL;
 	kfree(tu->tqueue);
```
