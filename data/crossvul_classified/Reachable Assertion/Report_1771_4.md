# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 1771_4
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1771_4`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 7-47 of the vulnerable file.

 * copyright notice and this permission notice appear in all copies.
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

#ifdef ENABLE_SONMP

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>

static struct sonmp_chassis sonmp_chassis_types[] = {
	{1, "unknown (via SONMP)"},
	{2, "Nortel 3000"},
	{3, "Nortel 3030"},
	{4, "Nortel 2310"},
	{5, "Nortel 2810"},
	{6, "Nortel 2912"},
	{7, "Nortel 2914"},
	{8, "Nortel 271x"},
	{9, "Nortel 2813"},
	{10, "Nortel 2814"},
	{11, "Nortel 2915"},
	{12, "Nortel 5000"},
	{13, "Nortel 2813SA"},
	{14, "Nortel 2814SA"},
	{15, "Nortel 810M"},
	{16, "Nortel EtherCell"},
	{17, "Nortel 5005"},
	{18, "Alcatel Ethernet workgroup conc."},
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,7 +24,6 @@
 #include <unistd.h>
 #include <errno.h>
 #include <arpa/inet.h>
-#include <assert.h>
 
 static struct sonmp_chassis sonmp_chassis_types[] = {
 	{1, "unknown (via SONMP)"},
@@ -358,8 +357,11 @@
 	}
 	mgmt = lldpd_alloc_mgmt(LLDPD_AF_IPV4, &address, sizeof(struct in_addr), 0);
 	if (mgmt == NULL) {
-		assert(errno == ENOMEM);
-		log_warn("sonmp", "unable to allocate memory for management address");
+		if (errno == ENOMEM)
+			log_warn("sonmp", "unable to allocate memory for management address");
+		else
+			log_warn("sonmp", "too large management address received on %s",
+			    hardware->h_ifname);
 		goto malformed;
 	}
 	TAILQ_INSERT_TAIL(&chassis->c_mgmt, mgmt, m_entries);
```
