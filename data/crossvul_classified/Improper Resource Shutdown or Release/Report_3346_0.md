# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3346_0
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3346_0`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 125-170 of the vulnerable file.

	if (!od)
		return -ENOMEM;

	usb_set_serial_port_data(port, od);

	return 0;
}

static int omninet_port_remove(struct usb_serial_port *port)
{
	struct omninet_data *od;

	od = usb_get_serial_port_data(port);
	kfree(od);

	return 0;
}

static int omninet_open(struct tty_struct *tty, struct usb_serial_port *port)
{
	struct usb_serial	*serial = port->serial;
	struct usb_serial_port	*wport;

	wport = serial->port[1];
	tty_port_tty_set(&wport->port, tty);

	return usb_serial_generic_open(tty, port);
}

#define OMNINET_HEADERLEN	4
#define OMNINET_BULKOUTSIZE	64
#define OMNINET_PAYLOADSIZE	(OMNINET_BULKOUTSIZE - OMNINET_HEADERLEN)

static void omninet_process_read_urb(struct urb *urb)
{
	struct usb_serial_port *port = urb->context;
	const struct omninet_header *hdr = urb->transfer_buffer;
	const unsigned char *data;
	size_t data_len;

	if (urb->actual_length <= OMNINET_HEADERLEN || !hdr->oh_len)
		return;

	data = (char *)urb->transfer_buffer + OMNINET_HEADERLEN;
	data_len = min_t(size_t, urb->actual_length - OMNINET_HEADERLEN,
								hdr->oh_len);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,12 +142,6 @@
 
 static int omninet_open(struct tty_struct *tty, struct usb_serial_port *port)
 {
-	struct usb_serial	*serial = port->serial;
-	struct usb_serial_port	*wport;
-
-	wport = serial->port[1];
-	tty_port_tty_set(&wport->port, tty);
-
 	return usb_serial_generic_open(tty, port);
 }
 
```
