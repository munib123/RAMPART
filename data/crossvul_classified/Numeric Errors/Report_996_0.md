# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 996_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `996_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 149-189 of the vulnerable file.

}

/**
 * dwc3_ep_inc_enq - increment endpoint's enqueue pointer
 * @dep: The endpoint whose enqueue pointer we're incrementing
 */
static void dwc3_ep_inc_enq(struct dwc3_ep *dep)
{
	dwc3_ep_inc_trb(&dep->trb_enqueue);
}

/**
 * dwc3_ep_inc_deq - increment endpoint's dequeue pointer
 * @dep: The endpoint whose enqueue pointer we're incrementing
 */
static void dwc3_ep_inc_deq(struct dwc3_ep *dep)
{
	dwc3_ep_inc_trb(&dep->trb_dequeue);
}

/**
 * dwc3_gadget_giveback - call struct usb_request's ->complete callback
 * @dep: The endpoint to whom the request belongs to
 * @req: The request we're giving back
 * @status: completion code for the request
 *
 * Must be called with controller's lock held and interrupts disabled. This
 * function will unmap @req and call its ->complete() callback to notify upper
 * layers that it has completed.
 */
void dwc3_gadget_giveback(struct dwc3_ep *dep, struct dwc3_request *req,
		int status)
{
	struct dwc3			*dwc = dep->dwc;

	req->started = false;
	list_del(&req->list);
	req->remaining = 0;

	if (req->request.status == -EINPROGRESS)
		req->request.status = status;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -166,6 +166,29 @@
 	dwc3_ep_inc_trb(&dep->trb_dequeue);
 }
 
+void dwc3_gadget_del_and_unmap_request(struct dwc3_ep *dep,
+		struct dwc3_request *req, int status)
+{
+	struct dwc3			*dwc = dep->dwc;
+
+	req->started = false;
+	list_del(&req->list);
+	req->remaining = 0;
+
+	if (req->request.status == -EINPROGRESS)
+		req->request.status = status;
+
+	if (req->trb)
+		usb_gadget_unmap_request_by_dev(dwc->sysdev,
+				&req->request, req->direction);
+
+	req->trb = NULL;
+	trace_dwc3_gadget_giveback(req);
+
+	if (dep->number > 1)
+		pm_runtime_put(dwc->dev);
+}
+
 /**
  * dwc3_gadget_giveback - call struct usb_request's ->complete callback
  * @dep: The endpoint to whom the request belongs to
@@ -181,27 +204,11 @@
 {
 	struct dwc3			*dwc = dep->dwc;
 
-	req->started = false;
-	list_del(&req->list);
-	req->remaining = 0;
-
-	if (req->request.status == -EINPROGRESS)
-		req->request.status = status;
-
-	if (req->trb)
-		usb_gadget_unmap_request_by_dev(dwc->sysdev,
-						&req->request, req->direction);
-
-	req->trb = NULL;
-
-	trace_dwc3_gadget_giveback(req);
+	dwc3_gadget_del_and_unmap_request(dep, req, status);
 
 	spin_unlock(&dwc->lock);
 	usb_gadget_giveback_request(&dep->endpoint, &req->request);
 	spin_lock(&dwc->lock);
-
-	if (dep->number > 1)
-		pm_runtime_put(dwc->dev);
 }
 
 /**
@@ -1227,7 +1234,7 @@
 		if (req->trb)
 			memset(req->trb, 0, sizeof(struct dwc3_trb));
 		dep->queued_requests--;
-		dwc3_gadget_giveback(dep, req, ret);
+		dwc3_gadget_del_and_unmap_request(dep, req, ret);
 		return ret;
 	}
 
```
