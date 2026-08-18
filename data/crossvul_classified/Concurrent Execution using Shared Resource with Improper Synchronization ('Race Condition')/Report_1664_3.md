# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1664_3
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1664_3`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 81-121 of the vulnerable file.

	{
		res = HSM_COM_NO_MEM;
		goto cleanup;
	}

	if((hdl->send_buf = malloc(max_data_len)) == NULL) 
	{
		res = HSM_COM_NO_MEM;
		goto cleanup;
	}

	hdl->scr.scratch_fill = 0;
	hdl->scr.scratch_len = max_data_len;
	hdl->buf_len = max_data_len;
	hdl->trans_id = 1;


	strcpy(hdl->s_path,server_path);
	strcpy(hdl->c_path,client_path);


	hdl->client_state = HSM_COM_C_STATE_IN;

	*p_hdl = hdl;

	return res;

cleanup:
	if(hdl)
	{
		if (hdl->scr.scratch) {
			free(hdl->scr.scratch);
		}
		if (hdl->recv_buf) {
			free(hdl->recv_buf);
		}
		free(hdl);
	}

	return res;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,6 +98,11 @@
 	strcpy(hdl->s_path,server_path);
 	strcpy(hdl->c_path,client_path);
 
+	if (mkstemp(hdl->c_path) == -1)
+	{
+		res = HSM_COM_PATH_ERR;
+		goto cleanup;
+	}
 
 	hdl->client_state = HSM_COM_C_STATE_IN;
 
```
