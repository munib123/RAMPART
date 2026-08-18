# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5757_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5757_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 137-177 of the vulnerable file.

	ctx->rd_out = ix;
out1:
	oz_cdev_release_ctx(ctx);
out2:
	oz_pd_put(pd);
	return count;
}

/*
 * Context: process
 */
static ssize_t oz_cdev_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *fpos)
{
	struct oz_pd *pd;
	struct oz_elt_buf *eb;
	struct oz_elt_info *ei;
	struct oz_elt *elt;
	struct oz_app_hdr *app_hdr;
	struct oz_serial_ctx *ctx;

	spin_lock_bh(&g_cdev.lock);
	pd = g_cdev.active_pd;
	if (pd)
		oz_pd_get(pd);
	spin_unlock_bh(&g_cdev.lock);
	if (pd == NULL)
		return -ENXIO;
	if (!(pd->state & OZ_PD_S_CONNECTED))
		return -EAGAIN;
	eb = &pd->elt_buff;
	ei = oz_elt_info_alloc(eb);
	if (ei == NULL) {
		count = 0;
		goto out;
	}
	elt = (struct oz_elt *)ei->data;
	app_hdr = (struct oz_app_hdr *)(elt+1);
	elt->length = sizeof(struct oz_app_hdr) + count;
	elt->type = OZ_ELT_APP_DATA;
	ei->app_id = OZ_APPID_SERIAL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,6 +155,9 @@
 	struct oz_app_hdr *app_hdr;
 	struct oz_serial_ctx *ctx;
 
+	if (count > sizeof(ei->data) - sizeof(*elt) - sizeof(*app_hdr))
+		return -EINVAL;
+
 	spin_lock_bh(&g_cdev.lock);
 	pd = g_cdev.active_pd;
 	if (pd)
```
