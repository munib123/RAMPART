# CrossVul Fix Pair: Double Free in c
**Pair ID:** 547_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `547_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 387-427 of the vulnerable file.


		req->length = 0;
		req->complete = f_midi_complete;

		kfifo_put(&midi->in_req_fifo, req);
	}

	/* allocate a bunch of read buffers and queue them all at once. */
	for (i = 0; i < midi->qlen && err == 0; i++) {
		struct usb_request *req =
			midi_alloc_ep_req(midi->out_ep, midi->buflen);

		if (req == NULL)
			return -ENOMEM;

		req->complete = f_midi_complete;
		err = usb_ep_queue(midi->out_ep, req, GFP_ATOMIC);
		if (err) {
			ERROR(midi, "%s: couldn't enqueue request: %d\n",
				    midi->out_ep->name, err);
			free_ep_req(midi->out_ep, req);
			return err;
		}
	}

	return 0;
}

static void f_midi_disable(struct usb_function *f)
{
	struct f_midi *midi = func_to_midi(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	struct usb_request *req = NULL;

	DBG(cdev, "disable\n");

	/*
	 * just disable endpoints, forcing completion of pending i/o.
	 * all our completion handlers free their requests in this case.
	 */
	usb_ep_disable(midi->in_ep);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -404,7 +404,8 @@
 		if (err) {
 			ERROR(midi, "%s: couldn't enqueue request: %d\n",
 				    midi->out_ep->name, err);
-			free_ep_req(midi->out_ep, req);
+			if (req->buf != NULL)
+				free_ep_req(midi->out_ep, req);
 			return err;
 		}
 	}
```
