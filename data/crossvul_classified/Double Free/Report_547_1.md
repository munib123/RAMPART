# CrossVul Fix Pair: Double Free in c
**Pair ID:** 547_1
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `547_1`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 44-68 of the vulnerable file.

struct usb_ep;
struct usb_request;

/**
 * alloc_ep_req - returns a usb_request allocated by the gadget driver and
 * allocates the request's buffer.
 *
 * @ep: the endpoint to allocate a usb_request
 * @len: usb_requests's buffer suggested size
 *
 * In case @ep direction is OUT, the @len will be aligned to ep's
 * wMaxPacketSize. In order to avoid memory leaks or drops, *always* use
 * usb_requests's length (req->length) to refer to the allocated buffer size.
 * Requests allocated via alloc_ep_req() *must* be freed by free_ep_req().
 */
struct usb_request *alloc_ep_req(struct usb_ep *ep, size_t len);

/* Frees a usb_request previously allocated by alloc_ep_req() */
static inline void free_ep_req(struct usb_ep *ep, struct usb_request *req)
{
	kfree(req->buf);
	usb_ep_free_request(ep, req);
}

#endif /* __U_F_H__ */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,7 +61,9 @@
 /* Frees a usb_request previously allocated by alloc_ep_req() */
 static inline void free_ep_req(struct usb_ep *ep, struct usb_request *req)
 {
+	WARN_ON(req->buf == NULL);
 	kfree(req->buf);
+	req->buf = NULL;
 	usb_ep_free_request(ep, req);
 }
 
```
