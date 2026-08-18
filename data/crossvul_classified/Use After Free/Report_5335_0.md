# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5335_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5335_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 629-669 of the vulnerable file.



/* "Normal" endpoints operations ********************************************/

static void ffs_epfile_io_complete(struct usb_ep *_ep, struct usb_request *req)
{
	ENTER();
	if (likely(req->context)) {
		struct ffs_ep *ep = _ep->driver_data;
		ep->status = req->status ? req->status : req->actual;
		complete(req->context);
	}
}

static void ffs_user_copy_worker(struct work_struct *work)
{
	struct ffs_io_data *io_data = container_of(work, struct ffs_io_data,
						   work);
	int ret = io_data->req->status ? io_data->req->status :
					 io_data->req->actual;

	if (io_data->read && ret > 0) {
		use_mm(io_data->mm);
		ret = copy_to_iter(io_data->buf, ret, &io_data->data);
		if (iov_iter_count(&io_data->data))
			ret = -EFAULT;
		unuse_mm(io_data->mm);
	}

	io_data->kiocb->ki_complete(io_data->kiocb, ret, ret);

	if (io_data->ffs->ffs_eventfd &&
	    !(io_data->kiocb->ki_flags & IOCB_EVENTFD))
		eventfd_signal(io_data->ffs->ffs_eventfd, 1);

	usb_ep_free_request(io_data->ep, io_data->req);

	io_data->kiocb->private = NULL;
	if (io_data->read)
		kfree(io_data->to_free);
	kfree(io_data->buf);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -646,6 +646,7 @@
 						   work);
 	int ret = io_data->req->status ? io_data->req->status :
 					 io_data->req->actual;
+	bool kiocb_has_eventfd = io_data->kiocb->ki_flags & IOCB_EVENTFD;
 
 	if (io_data->read && ret > 0) {
 		use_mm(io_data->mm);
@@ -657,13 +658,11 @@
 
 	io_data->kiocb->ki_complete(io_data->kiocb, ret, ret);
 
-	if (io_data->ffs->ffs_eventfd &&
-	    !(io_data->kiocb->ki_flags & IOCB_EVENTFD))
+	if (io_data->ffs->ffs_eventfd && !kiocb_has_eventfd)
 		eventfd_signal(io_data->ffs->ffs_eventfd, 1);
 
 	usb_ep_free_request(io_data->ep, io_data->req);
 
-	io_data->kiocb->private = NULL;
 	if (io_data->read)
 		kfree(io_data->to_free);
 	kfree(io_data->buf);
```
