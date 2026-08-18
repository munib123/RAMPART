# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 1613_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1613_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 12-43 of the vulnerable file.

 */
void oz_usb_get(void *hpd);
void oz_usb_put(void *hpd);

/* Stream functions.
 */
int oz_usb_stream_create(void *hpd, u8 ep_num);
int oz_usb_stream_delete(void *hpd, u8 ep_num);

/* Request functions.
 */
int oz_usb_control_req(void *hpd, u8 req_id, struct usb_ctrlrequest *setup,
		const u8 *data, int data_len);
int oz_usb_get_desc_req(void *hpd, u8 req_id, u8 req_type, u8 desc_type,
	u8 index, __le16 windex, int offset, int len);
int oz_usb_send_isoc(void *hpd, u8 ep_num, struct urb *urb);
void oz_usb_request_heartbeat(void *hpd);

/* Confirmation functions.
 */
void oz_hcd_get_desc_cnf(void *hport, u8 req_id, int status,
	const u8 *desc, int length, int offset, int total_size);
void oz_hcd_control_cnf(void *hport, u8 req_id, u8 rcode,
	const u8 *data, int data_len);

/* Indication functions.
 */
void oz_hcd_data_ind(void *hport, u8 endpoint, const u8 *data, int data_len);

int oz_hcd_heartbeat(void *hport);

#endif /* _OZUSBIF_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,8 +29,8 @@
 
 /* Confirmation functions.
  */
-void oz_hcd_get_desc_cnf(void *hport, u8 req_id, int status,
-	const u8 *desc, int length, int offset, int total_size);
+void oz_hcd_get_desc_cnf(void *hport, u8 req_id, u8 status,
+	const u8 *desc, u8 length, u16 offset, u16 total_size);
 void oz_hcd_control_cnf(void *hport, u8 req_id, u8 rcode,
 	const u8 *data, int data_len);
 
```
