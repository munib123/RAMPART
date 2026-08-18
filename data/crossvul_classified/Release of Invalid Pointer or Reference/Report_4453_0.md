# CrossVul Fix Pair: Release of Invalid Pointer or Reference in c
**Pair ID:** 4453_0
**Vulnerability Class:** Release of Invalid Pointer or Reference
**CWE:** CWE-763
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4453_0`)

## Vulnerability Information & PoC

## Description
Release of Invalid Pointer or Reference - This weakness can take several forms, such as: The memory was allocated, explicitly or implicitly, via one memory management method and deallocated using a different, non-compatible function (CWE-7...

## Vulnerable Code
```c
Lines 32-72 of the vulnerable file.

	*dev_no = MKDEV(4, (64 + ser));
	return 0;
}

static int get_dev_to_use(struct spk_synth *synth, dev_t *dev_no)
{
	/* use ser only when dev is not specified */
	if (strcmp(synth->dev_name, SYNTH_DEFAULT_DEV) ||
	    synth->ser == SYNTH_DEFAULT_SER)
		return tty_dev_name_to_number(synth->dev_name, dev_no);

	return ser_to_dev(synth->ser, dev_no);
}

static int spk_ttyio_ldisc_open(struct tty_struct *tty)
{
	struct spk_ldisc_data *ldisc_data;

	if (!tty->ops->write)
		return -EOPNOTSUPP;
	speakup_tty = tty;

	ldisc_data = kmalloc(sizeof(*ldisc_data), GFP_KERNEL);
	if (!ldisc_data)
		return -ENOMEM;

	init_completion(&ldisc_data->completion);
	ldisc_data->buf_free = true;
	speakup_tty->disc_data = ldisc_data;

	return 0;
}

static void spk_ttyio_ldisc_close(struct tty_struct *tty)
{
	mutex_lock(&speakup_tty_mutex);
	kfree(speakup_tty->disc_data);
	speakup_tty = NULL;
	mutex_unlock(&speakup_tty_mutex);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,15 +49,25 @@
 
 	if (!tty->ops->write)
 		return -EOPNOTSUPP;
+
+	mutex_lock(&speakup_tty_mutex);
+	if (speakup_tty) {
+		mutex_unlock(&speakup_tty_mutex);
+		return -EBUSY;
+	}
 	speakup_tty = tty;
 
 	ldisc_data = kmalloc(sizeof(*ldisc_data), GFP_KERNEL);
-	if (!ldisc_data)
+	if (!ldisc_data) {
+		speakup_tty = NULL;
+		mutex_unlock(&speakup_tty_mutex);
 		return -ENOMEM;
+	}
 
 	init_completion(&ldisc_data->completion);
 	ldisc_data->buf_free = true;
 	speakup_tty->disc_data = ldisc_data;
+	mutex_unlock(&speakup_tty_mutex);
 
 	return 0;
 }
```
