# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1858_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1858_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 770-810 of the vulnerable file.

	srp->data.cmd_opcode = cmnd[0];	/* hold opcode of command */
	hp->status = 0;
	hp->masked_status = 0;
	hp->msg_status = 0;
	hp->info = 0;
	hp->host_status = 0;
	hp->driver_status = 0;
	hp->resid = 0;
	SCSI_LOG_TIMEOUT(4, sg_printk(KERN_INFO, sfp->parentdp,
			"sg_common_write:  scsi opcode=0x%02x, cmd_size=%d\n",
			(int) cmnd[0], (int) hp->cmd_len));

	k = sg_start_req(srp, cmnd);
	if (k) {
		SCSI_LOG_TIMEOUT(1, sg_printk(KERN_INFO, sfp->parentdp,
			"sg_common_write: start_req err=%d\n", k));
		sg_finish_rem_req(srp);
		return k;	/* probably out of space --> ENOMEM */
	}
	if (atomic_read(&sdp->detaching)) {
		if (srp->bio)
			blk_end_request_all(srp->rq, -EIO);
		sg_finish_rem_req(srp);
		return -ENODEV;
	}

	hp->duration = jiffies_to_msecs(jiffies);
	if (hp->interface_id != '\0' &&	/* v3 (or later) interface */
	    (SG_FLAG_Q_AT_TAIL & hp->flags))
		at_head = 0;
	else
		at_head = 1;

	srp->rq->timeout = timeout;
	kref_get(&sfp->f_ref); /* sg_rq_end_io() does kref_put(). */
	blk_execute_rq_nowait(sdp->device->request_queue, sdp->disk,
			      srp->rq, at_head, sg_rq_end_io);
	return 0;
}

static int srp_done(Sg_fd *sfp, Sg_request *srp)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -787,8 +787,14 @@
 		return k;	/* probably out of space --> ENOMEM */
 	}
 	if (atomic_read(&sdp->detaching)) {
-		if (srp->bio)
+		if (srp->bio) {
+			if (srp->rq->cmd != srp->rq->__cmd)
+				kfree(srp->rq->cmd);
+
 			blk_end_request_all(srp->rq, -EIO);
+			srp->rq = NULL;
+		}
+
 		sg_finish_rem_req(srp);
 		return -ENODEV;
 	}
```
