# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1233_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1233_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 7170-7210 of the vulnerable file.

			 i40e_stat_str(hw, ret),
			 i40e_aq_str(hw, hw->aq.asq_last_status));
		return ret;
	}
	/* update the local VSI info with updated queue map */
	i40e_vsi_update_queue_map(vsi, &ctxt);
	vsi->info.valid_sections = 0;

	/* Create channels for macvlans */
	INIT_LIST_HEAD(&vsi->macvlan_list);
	for (i = 0; i < macvlan_cnt; i++) {
		ch = kzalloc(sizeof(*ch), GFP_KERNEL);
		if (!ch) {
			ret = -ENOMEM;
			goto err_free;
		}
		INIT_LIST_HEAD(&ch->list);
		ch->num_queue_pairs = qcnt;
		if (!i40e_setup_channel(pf, vsi, ch)) {
			ret = -EINVAL;
			goto err_free;
		}
		ch->parent_vsi = vsi;
		vsi->cnt_q_avail -= ch->num_queue_pairs;
		vsi->macvlan_cnt++;
		list_add_tail(&ch->list, &vsi->macvlan_list);
	}

	return ret;

err_free:
	dev_info(&pf->pdev->dev, "Failed to setup macvlans\n");
	i40e_free_macvlan_channels(vsi);

	return ret;
}

/**
 * i40e_fwd_add - configure macvlans
 * @netdev: net device to configure
 * @vdev: macvlan netdevice
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7187,6 +7187,7 @@
 		ch->num_queue_pairs = qcnt;
 		if (!i40e_setup_channel(pf, vsi, ch)) {
 			ret = -EINVAL;
+			kfree(ch);
 			goto err_free;
 		}
 		ch->parent_vsi = vsi;
```
