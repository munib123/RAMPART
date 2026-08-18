# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1249_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1249_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 90-136 of the vulnerable file.

			IWL_PRPH_SCRATCH_EARLY_DEBUG_EN |
			IWL_PRPH_SCRATCH_EDBG_DEST_DRAM;
	prph_sc_ctrl->control.control_flags = cpu_to_le32(control_flags);

	/* initialize RX default queue */
	prph_sc_ctrl->rbd_cfg.free_rbd_addr =
		cpu_to_le64(trans_pcie->rxq->bd_dma);

	/* Configure debug, for integration */
	if (!iwl_trans_dbg_ini_valid(trans))
		iwl_pcie_alloc_fw_monitor(trans, 0);
	if (trans->dbg.num_blocks) {
		prph_sc_ctrl->hwm_cfg.hwm_base_addr =
			cpu_to_le64(trans->dbg.fw_mon[0].physical);
		prph_sc_ctrl->hwm_cfg.hwm_size =
			cpu_to_le32(trans->dbg.fw_mon[0].size);
	}

	/* allocate ucode sections in dram and set addresses */
	ret = iwl_pcie_init_fw_sec(trans, fw, &prph_scratch->dram);
	if (ret) {
		dma_free_coherent(trans->dev,
				  sizeof(*prph_scratch),
				  prph_scratch,
				  trans_pcie->prph_scratch_dma_addr);
		return ret;
	}

	/* Allocate prph information
	 * currently we don't assign to the prph info anything, but it would get
	 * assigned later */
	prph_info = dma_alloc_coherent(trans->dev, sizeof(*prph_info),
				       &trans_pcie->prph_info_dma_addr,
				       GFP_KERNEL);
	if (!prph_info)
		return -ENOMEM;

	/* Allocate context info */
	ctxt_info_gen3 = dma_alloc_coherent(trans->dev,
					    sizeof(*ctxt_info_gen3),
					    &trans_pcie->ctxt_info_dma_addr,
					    GFP_KERNEL);
	if (!ctxt_info_gen3)
		return -ENOMEM;

	ctxt_info_gen3->prph_info_base_addr =
		cpu_to_le64(trans_pcie->prph_info_dma_addr);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,13 +107,9 @@
 
 	/* allocate ucode sections in dram and set addresses */
 	ret = iwl_pcie_init_fw_sec(trans, fw, &prph_scratch->dram);
-	if (ret) {
-		dma_free_coherent(trans->dev,
-				  sizeof(*prph_scratch),
-				  prph_scratch,
-				  trans_pcie->prph_scratch_dma_addr);
-		return ret;
-	}
+	if (ret)
+		goto err_free_prph_scratch;
+
 
 	/* Allocate prph information
 	 * currently we don't assign to the prph info anything, but it would get
@@ -121,16 +117,20 @@
 	prph_info = dma_alloc_coherent(trans->dev, sizeof(*prph_info),
 				       &trans_pcie->prph_info_dma_addr,
 				       GFP_KERNEL);
-	if (!prph_info)
-		return -ENOMEM;
+	if (!prph_info) {
+		ret = -ENOMEM;
+		goto err_free_prph_scratch;
+	}
 
 	/* Allocate context info */
 	ctxt_info_gen3 = dma_alloc_coherent(trans->dev,
 					    sizeof(*ctxt_info_gen3),
 					    &trans_pcie->ctxt_info_dma_addr,
 					    GFP_KERNEL);
-	if (!ctxt_info_gen3)
-		return -ENOMEM;
+	if (!ctxt_info_gen3) {
+		ret = -ENOMEM;
+		goto err_free_prph_info;
+	}
 
 	ctxt_info_gen3->prph_info_base_addr =
 		cpu_to_le64(trans_pcie->prph_info_dma_addr);
@@ -186,6 +186,20 @@
 		iwl_set_bit(trans, CSR_GP_CNTRL, CSR_AUTO_FUNC_INIT);
 
 	return 0;
+
+err_free_prph_info:
+	dma_free_coherent(trans->dev,
+			  sizeof(*prph_info),
+			prph_info,
+			trans_pcie->prph_info_dma_addr);
+
+err_free_prph_scratch:
+	dma_free_coherent(trans->dev,
+			  sizeof(*prph_scratch),
+			prph_scratch,
+			trans_pcie->prph_scratch_dma_addr);
+	return ret;
+
 }
 
 void iwl_pcie_ctxt_info_gen3_free(struct iwl_trans *trans)
```
