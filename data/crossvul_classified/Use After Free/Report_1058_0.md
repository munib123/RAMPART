# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1058_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1058_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 3431-3472 of the vulnerable file.

	unsigned int total_len;
	int flags = CIFS_LOG_ERROR;
	struct cifs_ses *ses = io_parms->tcon->ses;

	*nbytes = 0;
	rc = smb2_new_read_req((void **)&req, &total_len, io_parms, NULL, 0, 0);
	if (rc)
		return rc;

	if (smb3_encryption_required(io_parms->tcon))
		flags |= CIFS_TRANSFORM_REQ;

	iov[0].iov_base = (char *)req;
	iov[0].iov_len = total_len;

	memset(&rqst, 0, sizeof(struct smb_rqst));
	rqst.rq_iov = iov;
	rqst.rq_nvec = 1;

	rc = cifs_send_recv(xid, ses, &rqst, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);

	rsp = (struct smb2_read_rsp *)rsp_iov.iov_base;

	if (rc) {
		if (rc != -ENODATA) {
			cifs_stats_fail_inc(io_parms->tcon, SMB2_READ_HE);
			cifs_dbg(VFS, "Send error in read = %d\n", rc);
			trace_smb3_read_err(xid, req->PersistentFileId,
					    io_parms->tcon->tid, ses->Suid,
					    io_parms->offset, io_parms->length,
					    rc);
		} else
			trace_smb3_read_done(xid, req->PersistentFileId,
				    io_parms->tcon->tid, ses->Suid,
				    io_parms->offset, 0);
		free_rsp_buf(resp_buftype, rsp_iov.iov_base);
		return rc == -ENODATA ? 0 : rc;
	} else
		trace_smb3_read_done(xid, req->PersistentFileId,
				    io_parms->tcon->tid, ses->Suid,
				    io_parms->offset, io_parms->length);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3448,8 +3448,6 @@
 	rqst.rq_nvec = 1;
 
 	rc = cifs_send_recv(xid, ses, &rqst, &resp_buftype, flags, &rsp_iov);
-	cifs_small_buf_release(req);
-
 	rsp = (struct smb2_read_rsp *)rsp_iov.iov_base;
 
 	if (rc) {
@@ -3470,6 +3468,8 @@
 		trace_smb3_read_done(xid, req->PersistentFileId,
 				    io_parms->tcon->tid, ses->Suid,
 				    io_parms->offset, io_parms->length);
+
+	cifs_small_buf_release(req);
 
 	*nbytes = le32_to_cpu(rsp->DataLength);
 	if ((*nbytes > CIFS_MAX_MSGSIZE) ||
```
