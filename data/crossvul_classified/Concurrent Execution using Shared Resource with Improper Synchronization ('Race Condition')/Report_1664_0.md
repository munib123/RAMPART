# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1664_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1664_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 15-55 of the vulnerable file.

      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 * ** END_ICS_COPYRIGHT2   ****************************************/

#ifndef HSM_CONFIG_SRVR_DATA
#define	HSM_CONFIG_SRVR_DATA

#include "hsm_config_srvr_api.h"

#define HSM_FM_SCK_PREFIX	"/tmp/"
#define HSM_FM_SCK_SM		"sm_"
#define HSM_FM_SCK_PM		"pm_"
#define HSM_FM_SCK_BM		"bm_"
#define HSM_FM_SCK_FE		"fe_"

typedef struct	_fm_config_conx_hdl{
	unsigned				instance;
	unsigned				conx_mask; // Mask to store which services are currently connected.
	p_hsm_com_client_hdl_t	sm_hdl;
	p_hsm_com_client_hdl_t	pm_hdl;
	p_hsm_com_client_hdl_t	bm_hdl;
	p_hsm_com_client_hdl_t	fe_hdl;
	uint32_t				index_len;
	fm_error_map_t			error_map;
}fm_config_conx_hdl;

typedef struct fm_config_datagram_header_s{
	fm_msg_ret_code_t	ret_code;
	unsigned long		action;
	unsigned long		data_id;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,10 +32,9 @@
 
 #include "hsm_config_srvr_api.h"
 
-#define HSM_FM_SCK_PREFIX	"/tmp/"
+#define HSM_FM_SCK_PREFIX	"/opt/opafm/"
 #define HSM_FM_SCK_SM		"sm_"
 #define HSM_FM_SCK_PM		"pm_"
-#define HSM_FM_SCK_BM		"bm_"
 #define HSM_FM_SCK_FE		"fe_"
 
 typedef struct	_fm_config_conx_hdl{
```
