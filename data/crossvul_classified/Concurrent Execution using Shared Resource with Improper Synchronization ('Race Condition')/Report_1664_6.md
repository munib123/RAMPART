# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1664_6
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1664_6`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 16-56 of the vulnerable file.


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

#ifndef HSM_CONFIG_DATA
#define	HSM_CONFIG_DATA

#include "hsm_config_api.h"
#include "snmp_com_api.h"

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
	p_snmp_sess_hdl_t		snmp_sess;
	p_snmp_conx_hdl_t		snmp_conx;
	int						snmp_enabled;
	uint32_t				conx_index[MAX_OID_LEN];
	uint32_t				index_len;
}fm_config_conx_hdl;

typedef struct fm_config_datagram_header_s{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,10 +33,9 @@
 #include "hsm_config_api.h"
 #include "snmp_com_api.h"
 
-#define HSM_FM_SCK_PREFIX	"/tmp/"
+#define HSM_FM_SCK_PREFIX	"/opt/opafm/"
 #define HSM_FM_SCK_SM		"sm_"
 #define HSM_FM_SCK_PM		"pm_"
-#define HSM_FM_SCK_BM		"bm_"
 #define HSM_FM_SCK_FE		"fe_"
 
 typedef struct	_fm_config_conx_hdl{
```
