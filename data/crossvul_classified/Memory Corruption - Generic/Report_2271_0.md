# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2271_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2271_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 22-62 of the vulnerable file.

    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>

/* globals */

struct postgresql_status {
   u_char status;
   u_char user[65];
   u_char type;
   u_char password[65];
   u_char hash[33];
   u_char salt[9];
   u_char database[65];
};

#define WAIT_AUTH       1
#define WAIT_RESPONSE   2
#define WAIT_RESULT     3
#define MD5             1
#define CT              2

/* protos */

FUNC_DECODER(dissector_postgresql);
void postgresql_init(void);

/************************************************/

#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
    u_char status;
    u_char user[65];
    u_char type;
-   u_char password[65];
+   u_char password[66];
    u_char hash[33];
    u_char salt[9];
    u_char database[65];
@@ -157,8 +157,12 @@
                int length;
                DEBUG_MSG("\tDissector_postgresql RESPONSE type is clear-text!");
                GET_ULONG_BE(length, ptr, 1);
-               strncpy((char*)conn_status->password, (char*)(ptr + 5), length - 4);
-               conn_status->password[length - 4] = 0;
+               length -= 4;
+               if (length < 0 || length > 65 || PACKET->DATA.len < length+5) {
+                   dissect_wipe_session(PACKET, DISSECT_CODE(dissector_postgresql));
+                   return NULL;
+               }
+               snprintf((char*)conn_status->password, length+1, "%s", (char*)(ptr + 5));
                DISSECT_MSG("PostgreSQL credentials:%s-%d:%s:%s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp), ntohs(PACKET->L4.dst), conn_status->user, conn_status->password);
                dissect_wipe_session(PACKET, DISSECT_CODE(dissector_postgresql));
             }
```
