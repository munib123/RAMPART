# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3447_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3447_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 459-499 of the vulnerable file.


	leave_sysex(dev);

	/*
	 * Shut up the synths by sending just single active sensing message.
	 */
	midi_devs[orig_dev]->outputc(orig_dev, 0xfe);

	midi_devs[orig_dev]->close(orig_dev);
}
EXPORT_SYMBOL(midi_synth_close);

void
midi_synth_hw_control(int dev, unsigned char *event)
{
}
EXPORT_SYMBOL(midi_synth_hw_control);

int
midi_synth_load_patch(int dev, int format, const char __user *addr,
		      int offs, int count, int pmgr_flag)
{
	int             orig_dev = synth_devs[dev]->midi_dev;

	struct sysex_info sysex;
	int             i;
	unsigned long   left, src_offs, eox_seen = 0;
	int             first_byte = 1;
	int             hdr_size = (unsigned long) &sysex.data[0] - (unsigned long) &sysex;

	leave_sysex(dev);

	if (!prefix_cmd(orig_dev, 0xf0))
		return 0;

	if (format != SYSEX_PATCH)
	{
/*		  printk("MIDI Error: Invalid patch format (key) 0x%x\n", format);*/
		  return -EINVAL;
	}
	if (count < hdr_size)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -476,7 +476,7 @@
 
 int
 midi_synth_load_patch(int dev, int format, const char __user *addr,
-		      int offs, int count, int pmgr_flag)
+		      int count, int pmgr_flag)
 {
 	int             orig_dev = synth_devs[dev]->midi_dev;
 
@@ -491,33 +491,29 @@
 	if (!prefix_cmd(orig_dev, 0xf0))
 		return 0;
 
+	/* Invalid patch format */
 	if (format != SYSEX_PATCH)
-	{
-/*		  printk("MIDI Error: Invalid patch format (key) 0x%x\n", format);*/
 		  return -EINVAL;
-	}
+
+	/* Patch header too short */
 	if (count < hdr_size)
-	{
-/*		printk("MIDI Error: Patch header too short\n");*/
 		return -EINVAL;
-	}
+
 	count -= hdr_size;
 
 	/*
-	 * Copy the header from user space but ignore the first bytes which have
-	 * been transferred already.
+	 * Copy the header from user space
 	 */
 
-	if(copy_from_user(&((char *) &sysex)[offs], &(addr)[offs], hdr_size - offs))
+	if (copy_from_user(&sysex, addr, hdr_size))
 		return -EFAULT;
- 
- 	if (count < sysex.len)
-	{
-/*		printk(KERN_WARNING "MIDI Warning: Sysex record too short (%d<%d)\n", count, (int) sysex.len);*/
+
+	/* Sysex record too short */
+	if ((unsigned)count < (unsigned)sysex.len)
 		sysex.len = count;
-	}
-  	left = sysex.len;
-  	src_offs = 0;
+
+	left = sysex.len;
+	src_offs = 0;
 
 	for (i = 0; i < left && !signal_pending(current); i++)
 	{
```
