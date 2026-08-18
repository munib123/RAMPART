# CrossVul Fix Pair: Improper Initialization in c
**Pair ID:** 1128_0
**Vulnerability Class:** Improper Initialization
**CWE:** CWE-665
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1128_0`)

## Vulnerability Information & PoC

## Description
Improper Initialization - This can have security implications when the associated resource is expected to have certain properties or values, such as a variable that determines whether a user has been authenticated or not.

## Vulnerable Code
```c
Lines 321-361 of the vulnerable file.

	if (mask & IB_DEVICE_MODIFY_NODE_DESC) {
		spin_lock_irqsave(&to_hr_dev(ib_dev)->sm_lock, flags);
		memcpy(ib_dev->node_desc, props->node_desc, NODE_DESC_SIZE);
		spin_unlock_irqrestore(&to_hr_dev(ib_dev)->sm_lock, flags);
	}

	return 0;
}

static int hns_roce_modify_port(struct ib_device *ib_dev, u8 port_num, int mask,
				struct ib_port_modify *props)
{
	return 0;
}

static struct ib_ucontext *hns_roce_alloc_ucontext(struct ib_device *ib_dev,
						   struct ib_udata *udata)
{
	int ret = 0;
	struct hns_roce_ucontext *context;
	struct hns_roce_ib_alloc_ucontext_resp resp;
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);

	resp.qp_tab_size = hr_dev->caps.num_qps;

	context = kmalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return ERR_PTR(-ENOMEM);

	ret = hns_roce_uar_alloc(hr_dev, &context->uar);
	if (ret)
		goto error_fail_uar_alloc;

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RECORD_DB) {
		INIT_LIST_HEAD(&context->page_list);
		mutex_init(&context->page_mutex);
	}

	ret = ib_copy_to_udata(udata, &resp, sizeof(resp));
	if (ret)
		goto error_fail_copy_to_udata;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -338,7 +338,7 @@
 {
 	int ret = 0;
 	struct hns_roce_ucontext *context;
-	struct hns_roce_ib_alloc_ucontext_resp resp;
+	struct hns_roce_ib_alloc_ucontext_resp resp = {};
 	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);
 
 	resp.qp_tab_size = hr_dev->caps.num_qps;
```
