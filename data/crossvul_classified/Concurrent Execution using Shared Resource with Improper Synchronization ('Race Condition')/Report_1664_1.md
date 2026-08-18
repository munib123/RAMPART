# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1664_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1664_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 24-64 of the vulnerable file.

CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 * ** END_ICS_COPYRIGHT5   ****************************************/

/*
 * FILE NAME
 *    sm_diag.c
 *
 * DESCRIPTION
 *    FMI sm_diag utility used to control and diagnose a local SM instance
 *
 * RESPONSIBLE ENGINEER
 *    John Seraphin
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include "hsm_config_client_api.h"
#include "hsm_config_client_data.h"

extern int   getopt(int, char *const *, const char *);

typedef struct command_s{
	char *name;
	int (*cmdPtr)(p_fm_config_conx_hdlt hdl, fm_mgr_type_t mgr, int argc, char *argv[]);
	fm_mgr_type_t mgr;
	char *desc;
}command_t;

/* function prototypes */
int mgr_force_sweep(p_fm_config_conx_hdlt hdl, fm_mgr_type_t mgr, int argc, char *argv[]);
int sm_restore_priority(p_fm_config_conx_hdlt hdl, fm_mgr_type_t mgr, int argc, char *argv[]);
int sm_broadcast_xml_config(p_fm_config_conx_hdlt hdl, fm_mgr_type_t mgr, int argc, char *argv[]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,7 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <sys/types.h>
+#include <unistd.h>
 #include <sys/socket.h>
 #include <sys/un.h>
 #include <sys/stat.h>
@@ -48,6 +49,7 @@
 #include <time.h>
 #include "hsm_config_client_api.h"
 #include "hsm_config_client_data.h"
+#include "hsm_com_client_data.h"
 
 extern int   getopt(int, char *const *, const char *);
 
@@ -1045,7 +1047,7 @@
 }
 
 int main(int argc, char *argv[]) {
-	p_fm_config_conx_hdlt	hdl;
+	p_fm_config_conx_hdlt	hdl = NULL;
 	int						instance = 0;
 	fm_mgr_config_errno_t	res;
 	char					*rem_addr = NULL;
@@ -1087,18 +1089,19 @@
 	if((res = fm_mgr_config_init(&hdl,instance, rem_addr, community)) != FM_CONF_OK)
 	{
 		fprintf(stderr, "Failed to initialize the client handle: %d\n", res);
-		goto die_clean;
+		goto cleanup;
 	}
 
 	if((res = fm_mgr_config_connect(hdl)) != FM_CONF_OK)
 	{
 		fprintf(stderr, "Failed to connect: (%d) %s\n",res,fm_mgr_get_error_str(res));
-		goto die_clean;
+		goto cleanup;
 	}
 
 	for(i=0;i<commandListLen;i++){
 		if(strcmp(command,commandList[i].name) == 0){
-			return commandList[i].cmdPtr(hdl, commandList[i].mgr, (argc - optind), &argv[optind]);
+			res = commandList[i].cmdPtr(hdl, commandList[i].mgr, (argc - optind), &argv[optind]);
+			goto cleanup;
 		}
 	}
 
@@ -1106,7 +1109,26 @@
 	usage(argv[0]);
 	res = -1;
 
-die_clean:
-	if (hdl) free(hdl);
+cleanup:
+	if (hdl)
+	{
+		if (hdl->sm_hdl)
+		{
+			if (hdl->sm_hdl->c_path[0])
+				unlink(hdl->sm_hdl->c_path);
+		}
+		if (hdl->pm_hdl)
+		{
+			if (hdl->pm_hdl->c_path[0])
+				unlink(hdl->pm_hdl->c_path);
+		}
+		if (hdl->fe_hdl)
+		{
+			if (hdl->fe_hdl->c_path[0])
+				unlink(hdl->fe_hdl->c_path);
+		}
+		free(hdl);
+	}
+
 	return res;
 }
```
