# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2908_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2908_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 5-45 of the vulnerable file.


struct usb_mixer_interface {
	struct snd_usb_audio *chip;
	struct usb_host_interface *hostif;
	struct list_head list;
	unsigned int ignore_ctl_error;
	struct urb *urb;
	/* array[MAX_ID_ELEMS], indexed by unit id */
	struct usb_mixer_elem_list **id_elems;

	/* the usb audio specification version this interface complies to */
	int protocol;

	/* Sound Blaster remote control stuff */
	const struct rc_config *rc_cfg;
	u32 rc_code;
	wait_queue_head_t rc_waitq;
	struct urb *rc_urb;
	struct usb_ctrlrequest *rc_setup_packet;
	u8 rc_buffer[6];
};

#define MAX_CHANNELS	16	/* max logical channels */

enum {
	USB_MIXER_BOOLEAN,
	USB_MIXER_INV_BOOLEAN,
	USB_MIXER_S8,
	USB_MIXER_U8,
	USB_MIXER_S16,
	USB_MIXER_U16,
	USB_MIXER_S32,
	USB_MIXER_U32,
};

typedef void (*usb_mixer_elem_dump_func_t)(struct snd_info_buffer *buffer,
					 struct usb_mixer_elem_list *list);
typedef int (*usb_mixer_elem_resume_func_t)(struct usb_mixer_elem_list *elem);

struct usb_mixer_elem_list {
	struct usb_mixer_interface *mixer;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,8 @@
 	struct urb *rc_urb;
 	struct usb_ctrlrequest *rc_setup_packet;
 	u8 rc_buffer[6];
+
+	bool disconnected;
 };
 
 #define MAX_CHANNELS	16	/* max logical channels */
```
