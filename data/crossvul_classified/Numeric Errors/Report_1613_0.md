# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 1613_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1613_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 729-770 of the vulnerable file.

void oz_hcd_pd_reset(void *hpd, void *hport)
{
	/* Cleanup the current configuration and report reset to the core.
	 */
	struct oz_port *port = hport;
	struct oz_hcd *ozhcd = port->ozhcd;

	oz_dbg(ON, "PD Reset\n");
	spin_lock_bh(&port->port_lock);
	port->flags |= OZ_PORT_F_CHANGED;
	port->status |= USB_PORT_STAT_RESET;
	port->status |= (USB_PORT_STAT_C_RESET << 16);
	spin_unlock_bh(&port->port_lock);
	oz_clean_endpoints_for_config(ozhcd->hcd, port);
	usb_hcd_poll_rh_status(ozhcd->hcd);
}

/*
 * Context: softirq
 */
void oz_hcd_get_desc_cnf(void *hport, u8 req_id, int status, const u8 *desc,
			int length, int offset, int total_size)
{
	struct oz_port *port = hport;
	struct urb *urb;
	int err = 0;

	oz_dbg(ON, "oz_hcd_get_desc_cnf length = %d offs = %d tot_size = %d\n",
	       length, offset, total_size);
	urb = oz_find_urb_by_id(port, 0, req_id);
	if (!urb)
		return;
	if (status == 0) {
		int copy_len;
		int required_size = urb->transfer_buffer_length;

		if (required_size > total_size)
			required_size = total_size;
		copy_len = required_size-offset;
		if (length <= copy_len)
			copy_len = length;
		memcpy(urb->transfer_buffer+offset, desc, copy_len);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -746,8 +746,8 @@
 /*
  * Context: softirq
  */
-void oz_hcd_get_desc_cnf(void *hport, u8 req_id, int status, const u8 *desc,
-			int length, int offset, int total_size)
+void oz_hcd_get_desc_cnf(void *hport, u8 req_id, u8 status, const u8 *desc,
+			u8 length, u16 offset, u16 total_size)
 {
 	struct oz_port *port = hport;
 	struct urb *urb;
@@ -759,8 +759,8 @@
 	if (!urb)
 		return;
 	if (status == 0) {
-		int copy_len;
-		int required_size = urb->transfer_buffer_length;
+		unsigned int copy_len;
+		unsigned int required_size = urb->transfer_buffer_length;
 
 		if (required_size > total_size)
 			required_size = total_size;
```
