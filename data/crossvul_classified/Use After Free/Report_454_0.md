# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 454_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `454_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 665-705 of the vulnerable file.

			goto __error;
		err = snd_usb_create_mixer(chip, ifnum, ignore_ctl_error);
		if (err < 0)
			goto __error;
	}

	/* we are allowed to call snd_card_register() many times */
	err = snd_card_register(chip->card);
	if (err < 0)
		goto __error;

	usb_chip[chip->index] = chip;
	chip->num_interfaces++;
	usb_set_intfdata(intf, chip);
	atomic_dec(&chip->active);
	mutex_unlock(&register_mutex);
	return 0;

 __error:
	if (chip) {
		if (!chip->num_interfaces)
			snd_card_free(chip->card);
		atomic_dec(&chip->active);
	}
	mutex_unlock(&register_mutex);
	return err;
}

/*
 * we need to take care of counter, since disconnection can be called also
 * many times as well as usb_audio_probe().
 */
static void usb_audio_disconnect(struct usb_interface *intf)
{
	struct snd_usb_audio *chip = usb_get_intfdata(intf);
	struct snd_card *card;
	struct list_head *p;

	if (chip == (void *)-1L)
		return;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -682,9 +682,12 @@
 
  __error:
 	if (chip) {
+		/* chip->active is inside the chip->card object,
+		 * decrement before memory is possibly returned.
+		 */
+		atomic_dec(&chip->active);
 		if (!chip->num_interfaces)
 			snd_card_free(chip->card);
-		atomic_dec(&chip->active);
 	}
 	mutex_unlock(&register_mutex);
 	return err;
```
