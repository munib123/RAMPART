# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 1771_1
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1771_1`)

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

/* We also supports FDP which is very similar to CDPv1 */
#include "lldpd.h"
#include "frame.h"

#if defined (ENABLE_CDP) || defined (ENABLE_FDP)

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>

static int
cdp_send(struct lldpd *global,
	 struct lldpd_hardware *hardware, int version)
{
	const char *platform = "Unknown";
	struct lldpd_chassis *chassis;
	struct lldpd_mgmt *mgmt;
	struct lldpd_port *port;
	u_int8_t mcastaddr[] = CDP_MULTICAST_ADDR;
	u_int8_t llcorg[] = LLC_ORG_CISCO;
#ifdef ENABLE_FDP
	char *capstr;
#endif
	u_int16_t checksum;
	int length, i;
	u_int32_t cap;
	u_int8_t *packet;
	u_int8_t *pos, *pos_len_eh, *pos_llc, *pos_cdp, *pos_checksum, *tlv, *end;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,6 @@
 #include <unistd.h>
 #include <errno.h>
 #include <arpa/inet.h>
-#include <assert.h>
 
 static int
 cdp_send(struct lldpd *global,
@@ -438,8 +437,13 @@
 						mgmt = lldpd_alloc_mgmt(LLDPD_AF_IPV4, &addr, 
 									sizeof(struct in_addr), 0);
 						if (mgmt == NULL) {
-							assert(errno == ENOMEM);
-							log_warn("cdp", "unable to allocate memory for management address");
+							if (errno == ENOMEM)
+								log_warn("cdp",
+								    "unable to allocate memory for management address");
+							else
+								log_warn("cdp",
+								    "too large management address received on %s",
+								    hardware->h_ifname);
 							goto malformed;
 						}
 						TAILQ_INSERT_TAIL(&chassis->c_mgmt, mgmt, m_entries);
```
