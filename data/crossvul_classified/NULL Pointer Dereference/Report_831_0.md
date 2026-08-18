# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 831_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `831_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 4171-4211 of the vulnerable file.

			return -ENOMEM;
		}
	}

	for (i = 0; i < max_cmd; i++) {
		cmd = instance->cmd_list[i];
		memset(cmd, 0, sizeof(struct megasas_cmd));
		cmd->index = i;
		cmd->scmd = NULL;
		cmd->instance = instance;

		list_add_tail(&cmd->list, &instance->cmd_pool);
	}

	/*
	 * Create a frame pool and assign one frame to each cmd
	 */
	if (megasas_create_frame_pool(instance)) {
		dev_printk(KERN_DEBUG, &instance->pdev->dev, "Error creating frame DMA pool\n");
		megasas_free_cmds(instance);
	}

	return 0;
}

/*
 * dcmd_timeout_ocr_possible -	Check if OCR is possible based on Driver/FW state.
 * @instance:				Adapter soft state
 *
 * Return 0 for only Fusion adapter, if driver load/unload is not in progress
 * or FW is not under OCR.
 */
inline int
dcmd_timeout_ocr_possible(struct megasas_instance *instance) {

	if (instance->adapter_type == MFI_SERIES)
		return KILL_ADAPTER;
	else if (instance->unload ||
			test_bit(MEGASAS_FUSION_IN_RESET, &instance->reset_flags))
		return IGNORE_TIMEOUT;
	else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4188,6 +4188,7 @@
 	if (megasas_create_frame_pool(instance)) {
 		dev_printk(KERN_DEBUG, &instance->pdev->dev, "Error creating frame DMA pool\n");
 		megasas_free_cmds(instance);
+		return -ENOMEM;
 	}
 
 	return 0;
```
