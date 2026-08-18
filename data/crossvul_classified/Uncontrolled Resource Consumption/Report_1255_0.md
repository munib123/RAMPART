# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1255_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1255_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1509-1549 of the vulnerable file.

		curr_head += L1_CACHE_BYTES;
		phys_offset = (unsigned long)sde->head_dma -
			      (unsigned long)dd->sdma_heads_dma;
		sde->head_phys = dd->sdma_heads_phys + phys_offset;
		init_sdma_regs(sde, per_sdma_credits, idle_cnt);
	}
	dd->flags |= HFI1_HAS_SEND_DMA;
	dd->flags |= idle_cnt ? HFI1_HAS_SDMA_TIMEOUT : 0;
	dd->num_sdma = num_engines;
	ret = sdma_map_init(dd, port, ppd->vls_operational, NULL);
	if (ret < 0)
		goto bail;

	tmp_sdma_rht = kzalloc(sizeof(*tmp_sdma_rht), GFP_KERNEL);
	if (!tmp_sdma_rht) {
		ret = -ENOMEM;
		goto bail;
	}

	ret = rhashtable_init(tmp_sdma_rht, &sdma_rht_params);
	if (ret < 0)
		goto bail;
	dd->sdma_rht = tmp_sdma_rht;

	dd_dev_info(dd, "SDMA num_sdma: %u\n", dd->num_sdma);
	return 0;

bail:
	sdma_clean(dd, num_engines);
	return ret;
}

/**
 * sdma_all_running() - called when the link goes up
 * @dd: hfi1_devdata
 *
 * This routine moves all engines to the running state.
 */
void sdma_all_running(struct hfi1_devdata *dd)
{
	struct sdma_engine *sde;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1526,8 +1526,11 @@
 	}
 
 	ret = rhashtable_init(tmp_sdma_rht, &sdma_rht_params);
-	if (ret < 0)
+	if (ret < 0) {
+		kfree(tmp_sdma_rht);
 		goto bail;
+	}
+
 	dd->sdma_rht = tmp_sdma_rht;
 
 	dd_dev_info(dd, "SDMA num_sdma: %u\n", dd->num_sdma);
```
