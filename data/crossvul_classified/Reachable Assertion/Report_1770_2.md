# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 1770_2
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1770_2`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 8-48 of the vulnerable file.

 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "lldpd.h"
#include "frame.h"

#ifdef ENABLE_EDP

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fnmatch.h>
#include <assert.h>

static int seq = 0;

int
edp_send(struct lldpd *global,
	 struct lldpd_hardware *hardware)
{
	const u_int8_t mcastaddr[] = EDP_MULTICAST_ADDR;
	const u_int8_t llcorg[] = LLC_ORG_EXTREME;
	struct lldpd_chassis *chassis;
	int length, i, v;
	u_int8_t *packet, *pos, *pos_llc, *pos_len_eh, *pos_len_edp, *pos_edp, *tlv, *end;
	u_int16_t checksum;
#ifdef ENABLE_DOT1
	struct lldpd_vlan *vlan;
	unsigned int state = 0;
#endif
	u_int8_t edp_fakeversion[] = {7, 6, 4, 99};
	/* Subsequent XXX can be replaced by other values. We place
	   them here to ensure the position of "" to be a bit
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,6 @@
 #include <errno.h>
 #include <arpa/inet.h>
 #include <fnmatch.h>
-#include <assert.h>
 
 static int seq = 0;
 
```
