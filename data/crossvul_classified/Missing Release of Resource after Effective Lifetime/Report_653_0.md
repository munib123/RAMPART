# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 653_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `653_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 678-718 of the vulnerable file.

	if (!resp) {
		kfree(req);
		return -ENOMEM;
	}

	req[1] = SMP_REPORT_PHY_ERR_LOG;
	req[9] = phy->number;

	res = smp_execute_task(dev, req, RPEL_REQ_SIZE,
			            resp, RPEL_RESP_SIZE);

	if (!res)
		goto out;

	phy->invalid_dword_count = scsi_to_u32(&resp[12]);
	phy->running_disparity_error_count = scsi_to_u32(&resp[16]);
	phy->loss_of_dword_sync_count = scsi_to_u32(&resp[20]);
	phy->phy_reset_problem_count = scsi_to_u32(&resp[24]);

 out:
	kfree(resp);
	return res;

}

#ifdef CONFIG_SCSI_SAS_ATA

#define RPS_REQ_SIZE  16
#define RPS_RESP_SIZE 60

int sas_get_report_phy_sata(struct domain_device *dev, int phy_id,
			    struct smp_resp *rps_resp)
{
	int res;
	u8 *rps_req = alloc_smp_req(RPS_REQ_SIZE);
	u8 *resp = (u8 *)rps_resp;

	if (!rps_req)
		return -ENOMEM;

	rps_req[1] = SMP_REPORT_PHY_SATA;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -695,6 +695,7 @@
 	phy->phy_reset_problem_count = scsi_to_u32(&resp[24]);
 
  out:
+	kfree(req);
 	kfree(resp);
 	return res;
 
```
