# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 995_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `995_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 374-414 of the vulnerable file.

	}

	spin_lock_irqsave(&hidg->write_spinlock, flags);

	/* when our function has been disabled by host */
	if (!hidg->req) {
		free_ep_req(hidg->in_ep, req);
		/*
		 * TODO
		 * Should we fail with error here?
		 */
		goto try_again;
	}

	req->status   = 0;
	req->zero     = 0;
	req->length   = count;
	req->complete = f_hidg_req_complete;
	req->context  = hidg;

	status = usb_ep_queue(hidg->in_ep, req, GFP_ATOMIC);
	if (status < 0) {
		ERROR(hidg->func.config->cdev,
			"usb_ep_queue error on int endpoint %zd\n", status);
		goto release_write_pending_unlocked;
	} else {
		status = count;
	}
	spin_unlock_irqrestore(&hidg->write_spinlock, flags);

	return status;
release_write_pending:
	spin_lock_irqsave(&hidg->write_spinlock, flags);
release_write_pending_unlocked:
	hidg->write_pending = 0;
	spin_unlock_irqrestore(&hidg->write_spinlock, flags);

	wake_up(&hidg->write_queue);

	return status;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -391,20 +391,20 @@
 	req->complete = f_hidg_req_complete;
 	req->context  = hidg;
 
+	spin_unlock_irqrestore(&hidg->write_spinlock, flags);
+
 	status = usb_ep_queue(hidg->in_ep, req, GFP_ATOMIC);
 	if (status < 0) {
 		ERROR(hidg->func.config->cdev,
 			"usb_ep_queue error on int endpoint %zd\n", status);
-		goto release_write_pending_unlocked;
+		goto release_write_pending;
 	} else {
 		status = count;
 	}
-	spin_unlock_irqrestore(&hidg->write_spinlock, flags);
 
 	return status;
 release_write_pending:
 	spin_lock_irqsave(&hidg->write_spinlock, flags);
-release_write_pending_unlocked:
 	hidg->write_pending = 0;
 	spin_unlock_irqrestore(&hidg->write_spinlock, flags);
 
```
