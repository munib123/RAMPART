# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1257_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1257_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 172-212 of the vulnerable file.

		 "%s.%d.auto", device_name, r);
	dev = bus_find_device_by_name(&platform_bus_type, NULL, auto_dev_name);
	dev_info(dev, "device %s added to pm domain\n", auto_dev_name);

	return dev;
}

/**
 * acp_hw_init - start and test ACP block
 *
 * @adev: amdgpu_device pointer
 *
 */
static int acp_hw_init(void *handle)
{
	int r, i;
	uint64_t acp_base;
	u32 val = 0;
	u32 count = 0;
	struct device *dev;
	struct i2s_platform_data *i2s_pdata;

	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	const struct amdgpu_ip_block *ip_block =
		amdgpu_device_ip_get_ip_block(adev, AMD_IP_BLOCK_TYPE_ACP);

	if (!ip_block)
		return -EINVAL;

	r = amd_acp_hw_init(adev->acp.cgs_device,
			    ip_block->version->major, ip_block->version->minor);
	/* -ENODEV means board uses AZ rather than ACP */
	if (r == -ENODEV) {
		amdgpu_dpm_set_powergating_by_smu(adev, AMD_IP_BLOCK_TYPE_ACP, true);
		return 0;
	} else if (r) {
		return r;
	}

	if (adev->rmmio_size == 0 || adev->rmmio_size < 0x5289)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -189,7 +189,7 @@
 	u32 val = 0;
 	u32 count = 0;
 	struct device *dev;
-	struct i2s_platform_data *i2s_pdata;
+	struct i2s_platform_data *i2s_pdata = NULL;
 
 	struct amdgpu_device *adev = (struct amdgpu_device *)handle;
 
@@ -231,20 +231,21 @@
 	adev->acp.acp_cell = kcalloc(ACP_DEVS, sizeof(struct mfd_cell),
 							GFP_KERNEL);
 
-	if (adev->acp.acp_cell == NULL)
-		return -ENOMEM;
+	if (adev->acp.acp_cell == NULL) {
+		r = -ENOMEM;
+		goto failure;
+	}
 
 	adev->acp.acp_res = kcalloc(5, sizeof(struct resource), GFP_KERNEL);
 	if (adev->acp.acp_res == NULL) {
-		kfree(adev->acp.acp_cell);
-		return -ENOMEM;
+		r = -ENOMEM;
+		goto failure;
 	}
 
 	i2s_pdata = kcalloc(3, sizeof(struct i2s_platform_data), GFP_KERNEL);
 	if (i2s_pdata == NULL) {
-		kfree(adev->acp.acp_res);
-		kfree(adev->acp.acp_cell);
-		return -ENOMEM;
+		r = -ENOMEM;
+		goto failure;
 	}
 
 	switch (adev->asic_type) {
@@ -341,14 +342,14 @@
 	r = mfd_add_hotplug_devices(adev->acp.parent, adev->acp.acp_cell,
 								ACP_DEVS);
 	if (r)
-		return r;
+		goto failure;
 
 	for (i = 0; i < ACP_DEVS ; i++) {
 		dev = get_mfd_cell_dev(adev->acp.acp_cell[i].name, i);
 		r = pm_genpd_add_device(&adev->acp.acp_genpd->gpd, dev);
 		if (r) {
 			dev_err(dev, "Failed to add dev to genpd\n");
-			return r;
+			goto failure;
 		}
 	}
 
@@ -367,7 +368,8 @@
 			break;
 		if (--count == 0) {
 			dev_err(&adev->pdev->dev, "Failed to reset ACP\n");
-			return -ETIMEDOUT;
+			r = -ETIMEDOUT;
+			goto failure;
 		}
 		udelay(100);
 	}
@@ -384,7 +386,8 @@
 			break;
 		if (--count == 0) {
 			dev_err(&adev->pdev->dev, "Failed to reset ACP\n");
-			return -ETIMEDOUT;
+			r = -ETIMEDOUT;
+			goto failure;
 		}
 		udelay(100);
 	}
@@ -393,6 +396,13 @@
 	val &= ~ACP_SOFT_RESET__SoftResetAud_MASK;
 	cgs_write_register(adev->acp.cgs_device, mmACP_SOFT_RESET, val);
 	return 0;
+
+failure:
+	kfree(i2s_pdata);
+	kfree(adev->acp.acp_res);
+	kfree(adev->acp.acp_cell);
+	kfree(adev->acp.acp_genpd);
+	return r;
 }
 
 /**
```
