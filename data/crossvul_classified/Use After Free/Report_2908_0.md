# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2908_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2908_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 2217-2257 of the vulnerable file.

			return parse_audio_processing_unit(state, unitid, p1);
		else
			return 0; /* FIXME - effect units not implemented yet */
	case UAC1_EXTENSION_UNIT:
	/*   UAC2_PROCESSING_UNIT_V2 has the same value */
		if (state->mixer->protocol == UAC_VERSION_1)
			return parse_audio_extension_unit(state, unitid, p1);
		else /* UAC_VERSION_2 */
			return parse_audio_processing_unit(state, unitid, p1);
	case UAC2_EXTENSION_UNIT_V2:
		return parse_audio_extension_unit(state, unitid, p1);
	default:
		usb_audio_err(state->chip,
			"unit %u: unexpected type 0x%02x\n", unitid, p1[2]);
		return -EINVAL;
	}
}

static void snd_usb_mixer_free(struct usb_mixer_interface *mixer)
{
	kfree(mixer->id_elems);
	if (mixer->urb) {
		kfree(mixer->urb->transfer_buffer);
		usb_free_urb(mixer->urb);
	}
	usb_free_urb(mixer->rc_urb);
	kfree(mixer->rc_setup_packet);
	kfree(mixer);
}

static int snd_usb_mixer_dev_free(struct snd_device *device)
{
	struct usb_mixer_interface *mixer = device->device_data;
	snd_usb_mixer_free(mixer);
	return 0;
}

/*
 * create mixer controls
 *
 * walk through all UAC_OUTPUT_TERMINAL descriptors to search for mixers
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2234,6 +2234,9 @@
 
 static void snd_usb_mixer_free(struct usb_mixer_interface *mixer)
 {
+	/* kill pending URBs */
+	snd_usb_mixer_disconnect(mixer);
+
 	kfree(mixer->id_elems);
 	if (mixer->urb) {
 		kfree(mixer->urb->transfer_buffer);
@@ -2584,8 +2587,13 @@
 
 void snd_usb_mixer_disconnect(struct usb_mixer_interface *mixer)
 {
-	usb_kill_urb(mixer->urb);
-	usb_kill_urb(mixer->rc_urb);
+	if (mixer->disconnected)
+		return;
+	if (mixer->urb)
+		usb_kill_urb(mixer->urb);
+	if (mixer->rc_urb)
+		usb_kill_urb(mixer->rc_urb);
+	mixer->disconnected = true;
 }
 
 #ifdef CONFIG_PM
```
