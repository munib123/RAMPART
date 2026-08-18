# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 1771_3
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1771_3`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 3-43 of the vulnerable file.

 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
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

#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

inline static int
lldpd_af_to_lldp_proto(int af)
{
	switch (af) {
	case LLDPD_AF_IPV4:
		return LLDP_MGMT_ADDR_IP4;
	case LLDPD_AF_IPV6:
		return LLDP_MGMT_ADDR_IP6;
	default:
		return LLDP_MGMT_ADDR_NONE;
	}
}

inline static int
lldpd_af_from_lldp_proto(int proto)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,6 @@
 
 #include <unistd.h>
 #include <errno.h>
-#include <assert.h>
 #include <time.h>
 #include <sys/types.h>
 #include <sys/socket.h>
@@ -161,7 +160,7 @@
 	/* Management addresses */
 	TAILQ_FOREACH(mgmt, &chassis->c_mgmt, m_entries) {
 		proto = lldpd_af_to_lldp_proto(mgmt->m_family);
-		assert(proto != LLDP_MGMT_ADDR_NONE);
+		if (proto == LLDP_MGMT_ADDR_NONE) continue;
 		if (!(
 			  POKE_START_LLDP_TLV(LLDP_TLV_MGMT_ADDR) &&
 			  /* Size of the address, including its type */
@@ -749,9 +748,12 @@
 				iface = 0;
 			mgmt = lldpd_alloc_mgmt(af, addr_ptr, addr_length, iface);
 			if (mgmt == NULL) {
-				assert(errno == ENOMEM);
-				log_warn("lldp", "unable to allocate memory "
-				    "for management address");
+				if (errno == ENOMEM)
+					log_warn("lldp", "unable to allocate memory "
+					    "for management address");
+				else
+					log_warn("lldp", "too large management address "
+					    "received on %s", hardware->h_ifname);
 				goto malformed;
 			}
 			TAILQ_INSERT_TAIL(&chassis->c_mgmt, mgmt, m_entries);
```
