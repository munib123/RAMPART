# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1269_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1269_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 67-107 of the vulnerable file.

	if (copy_to_iter(skb->data, count, to) != count)
		count = -EFAULT;

	kfree_skb(skb);

	return count;
}

static ssize_t qrtr_tun_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *filp = iocb->ki_filp;
	struct qrtr_tun *tun = filp->private_data;
	size_t len = iov_iter_count(from);
	ssize_t ret;
	void *kbuf;

	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (!copy_from_iter_full(kbuf, len, from))
		return -EFAULT;

	ret = qrtr_endpoint_post(&tun->ep, kbuf, len);

	return ret < 0 ? ret : len;
}

static __poll_t qrtr_tun_poll(struct file *filp, poll_table *wait)
{
	struct qrtr_tun *tun = filp->private_data;
	__poll_t mask = 0;

	poll_wait(filp, &tun->readq, wait);

	if (!skb_queue_empty(&tun->queue))
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,11 +84,14 @@
 	if (!kbuf)
 		return -ENOMEM;
 
-	if (!copy_from_iter_full(kbuf, len, from))
+	if (!copy_from_iter_full(kbuf, len, from)) {
+		kfree(kbuf);
 		return -EFAULT;
+	}
 
 	ret = qrtr_endpoint_post(&tun->ep, kbuf, len);
 
+	kfree(kbuf);
 	return ret < 0 ? ret : len;
 }
 
```
