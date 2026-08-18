# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1664_4
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1664_4`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 35-75 of the vulnerable file.

#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include "hsm_com_client_api.h"
#include "hsm_config_client_api.h"
#include "hsm_config_client_data.h"
#include "iba/public/ibyteswap.h"
#include "ssapi_internal.h"

fm_mgr_config_errno_t
fm_mgr_config_mgr_connect
(
	fm_config_conx_hdl	*hdl, 
	fm_mgr_type_t 		mgr
)
{
	char                    s_path[256];
	char                    c_path[256];
	char                    *mgr_prefix;
	p_hsm_com_client_hdl_t  *mgr_hdl;
	pid_t                   pid;

	memset(s_path,0,sizeof(s_path));
	memset(c_path,0,sizeof(c_path));

	pid = getpid();

	switch ( mgr )
	{
		case FM_MGR_SM:
			mgr_prefix  = HSM_FM_SCK_SM;
			mgr_hdl     = &hdl->sm_hdl;
			break;
		case FM_MGR_PM:
			mgr_prefix  = HSM_FM_SCK_PM;
			mgr_hdl     = &hdl->pm_hdl;
			break;
		case FM_MGR_FE:
			mgr_prefix  = HSM_FM_SCK_FE;
			mgr_hdl     = &hdl->fe_hdl;
			break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,12 +52,9 @@
 	char                    c_path[256];
 	char                    *mgr_prefix;
 	p_hsm_com_client_hdl_t  *mgr_hdl;
-	pid_t                   pid;
 
 	memset(s_path,0,sizeof(s_path));
 	memset(c_path,0,sizeof(c_path));
-
-	pid = getpid();
 
 	switch ( mgr )
 	{
@@ -80,8 +77,7 @@
 	// Fill in the paths for the server and client sockets.
 	sprintf(s_path,"%s%s%d",HSM_FM_SCK_PREFIX,mgr_prefix,hdl->instance);
 
-	sprintf(c_path,"%s%s%d_C_%lu",HSM_FM_SCK_PREFIX,mgr_prefix,
-			hdl->instance, (long unsigned)pid);
+	sprintf(c_path,"%s%s%d_C_XXXXXX",HSM_FM_SCK_PREFIX,mgr_prefix,hdl->instance);
 
 	if ( *mgr_hdl == NULL )
 	{
@@ -147,17 +143,7 @@
 		}
 	}
 
-
-	return res;
-
-
-	cleanup:
-
-	if ( hdl ) {
-		free(hdl);
-		hdl = NULL;
-	}
-
+cleanup:
 	return res;
 }
 
```
