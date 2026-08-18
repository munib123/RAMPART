# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4834_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4834_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License with
  the Debian GNU/Linux distribution in /usr/share/common-licenses/GPL;
  if not, write to the Free Software Foundation, Inc., 51 Franklin St.,
  Fifth Floor, Boston, MA  02110-1301  USA
*/

#define BITLBEE_CORE
#include "bitlbee.h"
#include "ft.h"

file_transfer_t *imcb_file_send_start(struct im_connection *ic, char *handle, char *file_name, size_t file_size)
{
	bee_t *bee = ic->bee;
	bee_user_t *bu = bee_user_by_handle(bee, ic, handle);

	if (bee->ui->ft_in_start) {
		return bee->ui->ft_in_start(bee, bu, file_name, file_size);
	} else {
		return NULL;
	}
}

gboolean imcb_file_recv_start(struct im_connection *ic, file_transfer_t *ft)
{
	bee_t *bee = ic->bee;

	if (bee->ui->ft_out_start) {
		return bee->ui->ft_out_start(ic, ft);
	} else {
		return FALSE;
	}
}

void imcb_file_canceled(struct im_connection *ic, file_transfer_t *file, char *reason)
{
	bee_t *bee = ic->bee;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,7 @@
 	bee_t *bee = ic->bee;
 	bee_user_t *bu = bee_user_by_handle(bee, ic, handle);
 
-	if (bee->ui->ft_in_start) {
+	if (bee->ui->ft_in_start && bu) {
 		return bee->ui->ft_in_start(bee, bu, file_name, file_size);
 	} else {
 		return NULL;
```
