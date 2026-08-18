# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3447_4
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3447_4`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 224-264 of the vulnerable file.

	c = count;

	while (c >= 4)
	{
		if (copy_from_user((char *) event_rec, &(buf)[p], 4))
			goto out;
		ev_code = event_rec[0];

		if (ev_code == SEQ_FULLSIZE)
		{
			int err, fmt;

			dev = *(unsigned short *) &event_rec[2];
			if (dev < 0 || dev >= max_synthdev || synth_devs[dev] == NULL)
				return -ENXIO;

			if (!(synth_open_mask & (1 << dev)))
				return -ENXIO;

			fmt = (*(short *) &event_rec[0]) & 0xffff;
			err = synth_devs[dev]->load_patch(dev, fmt, buf, p + 4, c, 0);
			if (err < 0)
				return err;

			return err;
		}
		if (ev_code >= 128)
		{
			if (seq_mode == SEQ_2 && ev_code == SEQ_EXTENDED)
			{
				printk(KERN_WARNING "Sequencer: Invalid level 2 event %x\n", ev_code);
				return -EINVAL;
			}
			ev_size = 8;

			if (c < ev_size)
			{
				if (!seq_playing)
					seq_startplay();
				return count - c;
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -241,7 +241,7 @@
 				return -ENXIO;
 
 			fmt = (*(short *) &event_rec[0]) & 0xffff;
-			err = synth_devs[dev]->load_patch(dev, fmt, buf, p + 4, c, 0);
+			err = synth_devs[dev]->load_patch(dev, fmt, buf + p, c, 0);
 			if (err < 0)
 				return err;
 
```
