# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1236_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1236_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 3003-3043 of the vulnerable file.

			 bmc->id.device_id);
	} else {
		bmc = kzalloc(sizeof(*bmc), GFP_KERNEL);
		if (!bmc) {
			rv = -ENOMEM;
			goto out;
		}
		INIT_LIST_HEAD(&bmc->intfs);
		mutex_init(&bmc->dyn_mutex);
		INIT_WORK(&bmc->remove_work, cleanup_bmc_work);

		bmc->id = *id;
		bmc->dyn_id_set = 1;
		bmc->dyn_guid_set = guid_set;
		bmc->guid = *guid;
		bmc->dyn_id_expiry = jiffies + IPMI_DYN_DEV_ID_EXPIRY;

		bmc->pdev.name = "ipmi_bmc";

		rv = ida_simple_get(&ipmi_bmc_ida, 0, 0, GFP_KERNEL);
		if (rv < 0)
			goto out;
		bmc->pdev.dev.driver = &ipmidriver.driver;
		bmc->pdev.id = rv;
		bmc->pdev.dev.release = release_bmc_device;
		bmc->pdev.dev.type = &bmc_device_type;
		kref_init(&bmc->usecount);

		intf->bmc = bmc;
		mutex_lock(&bmc->dyn_mutex);
		list_add_tail(&intf->bmc_link, &bmc->intfs);
		mutex_unlock(&bmc->dyn_mutex);

		rv = platform_device_register(&bmc->pdev);
		if (rv) {
			dev_err(intf->si_dev,
				"Unable to register bmc device: %d\n",
				rv);
			goto out_list_del;
		}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3020,8 +3020,11 @@
 		bmc->pdev.name = "ipmi_bmc";
 
 		rv = ida_simple_get(&ipmi_bmc_ida, 0, 0, GFP_KERNEL);
-		if (rv < 0)
+		if (rv < 0) {
+			kfree(bmc);
 			goto out;
+		}
+
 		bmc->pdev.dev.driver = &ipmidriver.driver;
 		bmc->pdev.id = rv;
 		bmc->pdev.dev.release = release_bmc_device;
```
