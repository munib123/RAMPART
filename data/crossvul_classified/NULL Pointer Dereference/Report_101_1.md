# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 101_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `101_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 739-779 of the vulnerable file.


	/* BB add code to build os and lm fields */

	rc = SendReceive2(sess_data->xid, sess_data->ses,
				sess_data->iov, 2,
				&sess_data->buf0_type,
				CIFS_LOG_ERROR | CIFS_NEG_OP, &rsp_iov);
	cifs_small_buf_release(sess_data->iov[0].iov_base);
	memcpy(&sess_data->iov[0], &rsp_iov, sizeof(struct kvec));

	return rc;
}

static int
SMB2_sess_establish_session(struct SMB2_sess_data *sess_data)
{
	int rc = 0;
	struct cifs_ses *ses = sess_data->ses;

	mutex_lock(&ses->server->srv_mutex);
	if (ses->server->sign && ses->server->ops->generate_signingkey) {
		rc = ses->server->ops->generate_signingkey(ses);
		kfree(ses->auth_key.response);
		ses->auth_key.response = NULL;
		if (rc) {
			cifs_dbg(FYI,
				"SMB3 session key generation failed\n");
			mutex_unlock(&ses->server->srv_mutex);
			goto keygen_exit;
		}
	}
	if (!ses->server->session_estab) {
		ses->server->sequence_number = 0x2;
		ses->server->session_estab = true;
	}
	mutex_unlock(&ses->server->srv_mutex);

	cifs_dbg(FYI, "SMB2/3 session established successfully\n");
	spin_lock(&GlobalMid_Lock);
	ses->status = CifsGood;
	ses->need_reconnect = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -756,15 +756,13 @@
 	struct cifs_ses *ses = sess_data->ses;
 
 	mutex_lock(&ses->server->srv_mutex);
-	if (ses->server->sign && ses->server->ops->generate_signingkey) {
+	if (ses->server->ops->generate_signingkey) {
 		rc = ses->server->ops->generate_signingkey(ses);
-		kfree(ses->auth_key.response);
-		ses->auth_key.response = NULL;
 		if (rc) {
 			cifs_dbg(FYI,
 				"SMB3 session key generation failed\n");
 			mutex_unlock(&ses->server->srv_mutex);
-			goto keygen_exit;
+			return rc;
 		}
 	}
 	if (!ses->server->session_estab) {
@@ -778,12 +776,6 @@
 	ses->status = CifsGood;
 	ses->need_reconnect = false;
 	spin_unlock(&GlobalMid_Lock);
-
-keygen_exit:
-	if (!ses->server->sign) {
-		kfree(ses->auth_key.response);
-		ses->auth_key.response = NULL;
-	}
 	return rc;
 }
 
```
