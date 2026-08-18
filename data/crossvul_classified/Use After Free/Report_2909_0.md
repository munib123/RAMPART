# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2909_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2909_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 131-171 of the vulnerable file.

	atomic_dec(&snd_seq_in_init);
#ifdef CONFIG_SND_SEQUENCER_MODULE
	/* initial autoload only when snd-seq is a module */
	queue_autoload_drivers();
#endif
}
EXPORT_SYMBOL(snd_seq_autoload_init);

void snd_seq_autoload_exit(void)
{
	atomic_inc(&snd_seq_in_init);
}
EXPORT_SYMBOL(snd_seq_autoload_exit);

void snd_seq_device_load_drivers(void)
{
	queue_autoload_drivers();
	flush_work(&autoload_work);
}
EXPORT_SYMBOL(snd_seq_device_load_drivers);
#else
#define queue_autoload_drivers() /* NOP */
#endif

/*
 * device management
 */
static int snd_seq_device_dev_free(struct snd_device *device)
{
	struct snd_seq_device *dev = device->device_data;

	put_device(&dev->dev);
	return 0;
}

static int snd_seq_device_dev_register(struct snd_device *device)
{
	struct snd_seq_device *dev = device->device_data;
	int err;

	err = device_add(&dev->dev);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -148,8 +148,10 @@
 	flush_work(&autoload_work);
 }
 EXPORT_SYMBOL(snd_seq_device_load_drivers);
+#define cancel_autoload_drivers()	cancel_work_sync(&autoload_work)
 #else
 #define queue_autoload_drivers() /* NOP */
+#define cancel_autoload_drivers() /* NOP */
 #endif
 
 /*
@@ -159,6 +161,7 @@
 {
 	struct snd_seq_device *dev = device->device_data;
 
+	cancel_autoload_drivers();
 	put_device(&dev->dev);
 	return 0;
 }
```
