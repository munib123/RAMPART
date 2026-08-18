# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1664_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1664_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 228-268 of the vulnerable file.

		return HSM_COM_BAD;
	}

	msg = (hsm_com_msg_t*)hdl->recv_buf;
	if(msg->common.resp_code == HSM_COM_RESP_OK){
		memcpy(recv->buf,&msg->data[0],msg->common.payload_len);
		recv->data_len = msg->common.payload_len;
		return HSM_COM_OK;
	}

	return HSM_COM_BAD;

}


hsm_com_errno_t
unix_client_connect(hsm_com_client_hdl_t *hdl)
{
	int					fd, len;
	struct sockaddr_un	unix_addr;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) 
	{
		return HSM_COM_ERROR;
	}

	memset(&unix_addr,0,sizeof(unix_addr));

	unix_addr.sun_family = AF_UNIX;
	
	if(strlen(hdl->c_path) >= sizeof(unix_addr.sun_path))
	{
		close(fd);
		return HSM_COM_PATH_ERR;
	}

	snprintf(unix_addr.sun_path, sizeof(unix_addr.sun_path), "%s", hdl->c_path);

	len = SUN_LEN(&unix_addr);

	unlink(unix_addr.sun_path);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -245,6 +245,7 @@
 {
 	int					fd, len;
 	struct sockaddr_un	unix_addr;
+	hsm_com_errno_t		res = HSM_COM_OK;
 
 	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) 
 	{
@@ -257,8 +258,8 @@
 	
 	if(strlen(hdl->c_path) >= sizeof(unix_addr.sun_path))
 	{
-		close(fd);
-		return HSM_COM_PATH_ERR;
+		res = HSM_COM_PATH_ERR;
+		goto cleanup;
 	}
 
 	snprintf(unix_addr.sun_path, sizeof(unix_addr.sun_path), "%s", hdl->c_path);
@@ -269,17 +270,14 @@
 
 	if(bind(fd, (struct sockaddr *)&unix_addr, len) < 0)
 	{
-		unlink(hdl->c_path);
-		close(fd);
-
-		return HSM_COM_BIND_ERR;
+		res = HSM_COM_BIND_ERR;
+		goto cleanup;
 	}
 
 	if(chmod(unix_addr.sun_path, S_IRWXU) < 0)
 	{
-		unlink(hdl->c_path);
-		close(fd);
-		return HSM_COM_CHMOD_ERR;
+		res = HSM_COM_CHMOD_ERR;
+		goto cleanup;
 	}
 
 	memset(&unix_addr,0,sizeof(unix_addr));
@@ -292,9 +290,8 @@
 
 	if (connect(fd, (struct sockaddr *) &unix_addr, len) < 0) 
 	{
-		unlink(hdl->c_path);
-		close(fd);
-		return HSM_COM_CONX_ERR;
+		res = HSM_COM_CONX_ERR;
+		goto cleanup;
 	}
 
 	hdl->client_fd = fd;
@@ -304,12 +301,14 @@
 	if(unix_sck_send_conn(hdl, 2) != HSM_COM_OK)
 	{
 		hdl->client_state = HSM_COM_C_STATE_IN;
-		return HSM_COM_SEND_ERR;
-	}
-
-
-
-	return HSM_COM_OK;
+		res = HSM_COM_SEND_ERR;
+	}
+
+	return res;
+
+cleanup:
+	close(fd);
+	return res;
 
 }
 
```
