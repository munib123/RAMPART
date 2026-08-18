# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5186_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5186_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 39-79 of the vulnerable file.

			return 1;
	}
	return 0;
}

static void __user *u64_to_uptr(u64 value)
{
	if (is_compat_task())
		return compat_ptr(value);
	else
		return (void __user *)(unsigned long)value;
}

/*
 * Start SCLP request
 */
static int sclp_ctl_ioctl_sccb(void __user *user_area)
{
	struct sclp_ctl_sccb ctl_sccb;
	struct sccb_header *sccb;
	int rc;

	if (copy_from_user(&ctl_sccb, user_area, sizeof(ctl_sccb)))
		return -EFAULT;
	if (!sclp_ctl_cmdw_supported(ctl_sccb.cmdw))
		return -EOPNOTSUPP;
	sccb = (void *) get_zeroed_page(GFP_KERNEL | GFP_DMA);
	if (!sccb)
		return -ENOMEM;
	if (copy_from_user(sccb, u64_to_uptr(ctl_sccb.sccb), sizeof(*sccb))) {
		rc = -EFAULT;
		goto out_free;
	}
	if (sccb->length > PAGE_SIZE || sccb->length < 8)
		return -EINVAL;
	if (copy_from_user(sccb, u64_to_uptr(ctl_sccb.sccb), sccb->length)) {
		rc = -EFAULT;
		goto out_free;
	}
	rc = sclp_sync_request(ctl_sccb.cmdw, sccb);
	if (rc)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,7 @@
 {
 	struct sclp_ctl_sccb ctl_sccb;
 	struct sccb_header *sccb;
+	unsigned long copied;
 	int rc;
 
 	if (copy_from_user(&ctl_sccb, user_area, sizeof(ctl_sccb)))
@@ -65,14 +66,15 @@
 	sccb = (void *) get_zeroed_page(GFP_KERNEL | GFP_DMA);
 	if (!sccb)
 		return -ENOMEM;
-	if (copy_from_user(sccb, u64_to_uptr(ctl_sccb.sccb), sizeof(*sccb))) {
+	copied = PAGE_SIZE -
+		copy_from_user(sccb, u64_to_uptr(ctl_sccb.sccb), PAGE_SIZE);
+	if (offsetof(struct sccb_header, length) +
+	    sizeof(sccb->length) > copied || sccb->length > copied) {
 		rc = -EFAULT;
 		goto out_free;
 	}
-	if (sccb->length > PAGE_SIZE || sccb->length < 8)
-		return -EINVAL;
-	if (copy_from_user(sccb, u64_to_uptr(ctl_sccb.sccb), sccb->length)) {
-		rc = -EFAULT;
+	if (sccb->length < 8) {
+		rc = -EINVAL;
 		goto out_free;
 	}
 	rc = sclp_sync_request(ctl_sccb.cmdw, sccb);
```
