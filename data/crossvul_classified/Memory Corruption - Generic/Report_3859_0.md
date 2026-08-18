# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3859_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3859_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 18-58 of the vulnerable file.

 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *****************************************************************************/

#include <net/mac80211.h>

#include "iwl-dev.h"
#include "iwl-core.h"
#include "iwl-agn.h"
#include "iwl-trans.h"

/* priv->shrd->sta_lock must be held */
static void iwl_sta_ucode_activate(struct iwl_priv *priv, u8 sta_id)
{

	if (!(priv->stations[sta_id].used & IWL_STA_DRIVER_ACTIVE))
		IWL_ERR(priv, "ACTIVATE a non DRIVER active station id %u "
			"addr %pM\n",
			sta_id, priv->stations[sta_id].sta.sta.addr);

	if (priv->stations[sta_id].used & IWL_STA_UCODE_ACTIVE) {
		IWL_DEBUG_ASSOC(priv,
				"STA id %u addr %pM already present in uCode "
				"(according to driver)\n",
				sta_id, priv->stations[sta_id].sta.sta.addr);
	} else {
		priv->stations[sta_id].used |= IWL_STA_UCODE_ACTIVE;
		IWL_DEBUG_ASSOC(priv, "Added STA id %u addr %pM to uCode\n",
				sta_id, priv->stations[sta_id].sta.sta.addr);
	}
}

static int iwl_process_add_sta_resp(struct iwl_priv *priv,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,9 +35,12 @@
 #include "iwl-trans.h"
 
 /* priv->shrd->sta_lock must be held */
-static void iwl_sta_ucode_activate(struct iwl_priv *priv, u8 sta_id)
-{
-
+static int iwl_sta_ucode_activate(struct iwl_priv *priv, u8 sta_id)
+{
+	if (sta_id >= IWLAGN_STATION_COUNT) {
+		IWL_ERR(priv, "invalid sta_id %u", sta_id);
+		return -EINVAL;
+	}
 	if (!(priv->stations[sta_id].used & IWL_STA_DRIVER_ACTIVE))
 		IWL_ERR(priv, "ACTIVATE a non DRIVER active station id %u "
 			"addr %pM\n",
@@ -53,6 +56,7 @@
 		IWL_DEBUG_ASSOC(priv, "Added STA id %u addr %pM to uCode\n",
 				sta_id, priv->stations[sta_id].sta.sta.addr);
 	}
+	return 0;
 }
 
 static int iwl_process_add_sta_resp(struct iwl_priv *priv,
@@ -77,8 +81,7 @@
 	switch (pkt->u.add_sta.status) {
 	case ADD_STA_SUCCESS_MSK:
 		IWL_DEBUG_INFO(priv, "REPLY_ADD_STA PASSED\n");
-		iwl_sta_ucode_activate(priv, sta_id);
-		ret = 0;
+		ret = iwl_sta_ucode_activate(priv, sta_id);
 		break;
 	case ADD_STA_NO_ROOM_IN_TABLE:
 		IWL_ERR(priv, "Adding station %d failed, no room in table.\n",
```
