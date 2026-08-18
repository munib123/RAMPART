# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5209_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5209_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1653-1712 of the vulnerable file.

		ret = TCM_INVALID_CDB_FIELD;
		goto send_sense;
	}

	unpacked_lun = srpt_unpack_lun((uint8_t *)&srp_cmd->lun,
				       sizeof(srp_cmd->lun));
	rc = target_submit_cmd(cmd, ch->sess, srp_cmd->cdb,
			&send_ioctx->sense_data[0], unpacked_lun, data_len,
			TCM_SIMPLE_TAG, dir, TARGET_SCF_ACK_KREF);
	if (rc != 0) {
		ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		goto send_sense;
	}
	return 0;

send_sense:
	transport_send_check_condition_and_sense(cmd, ret, 0);
	return -1;
}

/**
 * srpt_rx_mgmt_fn_tag() - Process a task management function by tag.
 * @ch: RDMA channel of the task management request.
 * @fn: Task management function to perform.
 * @req_tag: Tag of the SRP task management request.
 * @mgmt_ioctx: I/O context of the task management request.
 *
 * Returns zero if the target core will process the task management
 * request asynchronously.
 *
 * Note: It is assumed that the initiator serializes tag-based task management
 * requests.
 */
static int srpt_rx_mgmt_fn_tag(struct srpt_send_ioctx *ioctx, u64 tag)
{
	struct srpt_device *sdev;
	struct srpt_rdma_ch *ch;
	struct srpt_send_ioctx *target;
	int ret, i;

	ret = -EINVAL;
	ch = ioctx->ch;
	BUG_ON(!ch);
	BUG_ON(!ch->sport);
	sdev = ch->sport->sdev;
	BUG_ON(!sdev);
	spin_lock_irq(&sdev->spinlock);
	for (i = 0; i < ch->rq_size; ++i) {
		target = ch->ioctx_ring[i];
		if (target->cmd.se_lun == ioctx->cmd.se_lun &&
		    target->cmd.tag == tag &&
		    srpt_get_cmd_state(target) != SRPT_STATE_DONE) {
			ret = 0;
			/* now let the target core abort &target->cmd; */
			break;
		}
	}
	spin_unlock_irq(&sdev->spinlock);
	return ret;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1670,47 +1670,6 @@
 	return -1;
 }
 
-/**
- * srpt_rx_mgmt_fn_tag() - Process a task management function by tag.
- * @ch: RDMA channel of the task management request.
- * @fn: Task management function to perform.
- * @req_tag: Tag of the SRP task management request.
- * @mgmt_ioctx: I/O context of the task management request.
- *
- * Returns zero if the target core will process the task management
- * request asynchronously.
- *
- * Note: It is assumed that the initiator serializes tag-based task management
- * requests.
- */
-static int srpt_rx_mgmt_fn_tag(struct srpt_send_ioctx *ioctx, u64 tag)
-{
-	struct srpt_device *sdev;
-	struct srpt_rdma_ch *ch;
-	struct srpt_send_ioctx *target;
-	int ret, i;
-
-	ret = -EINVAL;
-	ch = ioctx->ch;
-	BUG_ON(!ch);
-	BUG_ON(!ch->sport);
-	sdev = ch->sport->sdev;
-	BUG_ON(!sdev);
-	spin_lock_irq(&sdev->spinlock);
-	for (i = 0; i < ch->rq_size; ++i) {
-		target = ch->ioctx_ring[i];
-		if (target->cmd.se_lun == ioctx->cmd.se_lun &&
-		    target->cmd.tag == tag &&
-		    srpt_get_cmd_state(target) != SRPT_STATE_DONE) {
-			ret = 0;
-			/* now let the target core abort &target->cmd; */
-			break;
-		}
-	}
-	spin_unlock_irq(&sdev->spinlock);
-	return ret;
-}
-
 static int srp_tmr_to_tcm(int fn)
 {
 	switch (fn) {
@@ -1745,7 +1704,6 @@
 	struct se_cmd *cmd;
 	struct se_session *sess = ch->sess;
 	uint64_t unpacked_lun;
-	uint32_t tag = 0;
 	int tcm_tmr;
 	int rc;
 
@@ -1761,25 +1719,10 @@
 	srpt_set_cmd_state(send_ioctx, SRPT_STATE_MGMT);
 	send_ioctx->cmd.tag = srp_tsk->tag;
 	tcm_tmr = srp_tmr_to_tcm(srp_tsk->tsk_mgmt_func);
-	if (tcm_tmr < 0) {
-		send_ioctx->cmd.se_tmr_req->response =
-			TMR_TASK_MGMT_FUNCTION_NOT_SUPPORTED;
-		goto fail;
-	}
 	unpacked_lun = srpt_unpack_lun((uint8_t *)&srp_tsk->lun,
 				       sizeof(srp_tsk->lun));
-
-	if (srp_tsk->tsk_mgmt_func == SRP_TSK_ABORT_TASK) {
-		rc = srpt_rx_mgmt_fn_tag(send_ioctx, srp_tsk->task_tag);
-		if (rc < 0) {
-			send_ioctx->cmd.se_tmr_req->response =
-					TMR_TASK_DOES_NOT_EXIST;
-			goto fail;
-		}
-		tag = srp_tsk->task_tag;
-	}
 	rc = target_submit_tmr(&send_ioctx->cmd, sess, NULL, unpacked_lun,
-				srp_tsk, tcm_tmr, GFP_KERNEL, tag,
+				srp_tsk, tcm_tmr, GFP_KERNEL, srp_tsk->task_tag,
 				TARGET_SCF_ACK_KREF);
 	if (rc != 0) {
 		send_ioctx->cmd.se_tmr_req->response = TMR_FUNCTION_REJECTED;
```
