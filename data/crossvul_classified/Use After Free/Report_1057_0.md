# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1057_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1057_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 3752-3792 of the vulnerable file.

	req->Length = cpu_to_le32(io_parms->length);
	req->Offset = cpu_to_le64(io_parms->offset);
	req->DataOffset = cpu_to_le16(
				offsetof(struct smb2_write_req, Buffer));
	req->RemainingBytes = 0;

	trace_smb3_write_enter(xid, io_parms->persistent_fid,
		io_parms->tcon->tid, io_parms->tcon->ses->Suid,
		io_parms->offset, io_parms->length);

	iov[0].iov_base = (char *)req;
	/* 1 for Buffer */
	iov[0].iov_len = total_len - 1;

	memset(&rqst, 0, sizeof(struct smb_rqst));
	rqst.rq_iov = iov;
	rqst.rq_nvec = n_vec + 1;

	rc = cifs_send_recv(xid, io_parms->tcon->ses, &rqst,
			    &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_write_rsp *)rsp_iov.iov_base;

	if (rc) {
		trace_smb3_write_err(xid, req->PersistentFileId,
				     io_parms->tcon->tid,
				     io_parms->tcon->ses->Suid,
				     io_parms->offset, io_parms->length, rc);
		cifs_stats_fail_inc(io_parms->tcon, SMB2_WRITE_HE);
		cifs_dbg(VFS, "Send error in write = %d\n", rc);
	} else {
		*nbytes = le32_to_cpu(rsp->DataLength);
		trace_smb3_write_done(xid, req->PersistentFileId,
				     io_parms->tcon->tid,
				     io_parms->tcon->ses->Suid,
				     io_parms->offset, *nbytes);
	}

	free_rsp_buf(resp_buftype, rsp);
	return rc;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3769,7 +3769,6 @@
 
 	rc = cifs_send_recv(xid, io_parms->tcon->ses, &rqst,
 			    &resp_buftype, flags, &rsp_iov);
-	cifs_small_buf_release(req);
 	rsp = (struct smb2_write_rsp *)rsp_iov.iov_base;
 
 	if (rc) {
@@ -3787,6 +3786,7 @@
 				     io_parms->offset, *nbytes);
 	}
 
+	cifs_small_buf_release(req);
 	free_rsp_buf(resp_buftype, rsp);
 	return rc;
 }
```
