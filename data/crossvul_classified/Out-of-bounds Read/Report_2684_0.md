# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2684_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2684_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 11-51 of the vulnerable file.

 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* \summary: IPv6 mobility printer */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include "ip6.h"
#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

static const char tstr[] = "[|MOBILITY]";

/* Mobility header */
struct ip6_mobility {
	uint8_t ip6m_pproto;	/* following payload protocol (for PG) */
	uint8_t ip6m_len;	/* length in units of 8 octets */
	uint8_t ip6m_type;	/* message type */
	uint8_t reserved;	/* reserved */
	uint16_t ip6m_cksum;	/* sum of IPv6 pseudo-header and MH */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,7 @@
  */
 
 /* \summary: IPv6 mobility printer */
+/* RFC 3775 */
 
 #ifdef HAVE_CONFIG_H
 #include "config.h"
@@ -241,7 +242,7 @@
 	case IP6M_CAREOF_TEST_INIT:
 		hlen = IP6M_MINLEN;
 		if (ndo->ndo_vflag) {
-			ND_TCHECK2(*mh, hlen + 8);
+			ND_TCHECK_32BITS(&bp[hlen + 4]);
 			ND_PRINT((ndo, " %s Init Cookie=%08x:%08x",
 			       type == IP6M_HOME_TEST_INIT ? "Home" : "Care-of",
 			       EXTRACT_32BITS(&bp[hlen]),
@@ -255,7 +256,7 @@
 		ND_PRINT((ndo, " nonce id=0x%x", EXTRACT_16BITS(&mh->ip6m_data16[0])));
 		hlen = IP6M_MINLEN;
 		if (ndo->ndo_vflag) {
-			ND_TCHECK2(*mh, hlen + 8);
+			ND_TCHECK_32BITS(&bp[hlen + 4]);
 			ND_PRINT((ndo, " %s Init Cookie=%08x:%08x",
 			       type == IP6M_HOME_TEST ? "Home" : "Care-of",
 			       EXTRACT_32BITS(&bp[hlen]),
@@ -263,7 +264,7 @@
 		}
 		hlen += 8;
 		if (ndo->ndo_vflag) {
-			ND_TCHECK2(*mh, hlen + 8);
+			ND_TCHECK_32BITS(&bp[hlen + 4]);
 			ND_PRINT((ndo, " %s Keygen Token=%08x:%08x",
 			       type == IP6M_HOME_TEST ? "Home" : "Care-of",
 			       EXTRACT_32BITS(&bp[hlen]),
@@ -275,22 +276,23 @@
 		ND_TCHECK(mh->ip6m_data16[0]);
 		ND_PRINT((ndo, " seq#=%u", EXTRACT_16BITS(&mh->ip6m_data16[0])));
 		hlen = IP6M_MINLEN;
-		ND_TCHECK2(*mh, hlen + 1);
-		if (bp[hlen] & 0xf0)
+		ND_TCHECK_16BITS(&bp[hlen]);
+		if (bp[hlen] & 0xf0) {
 			ND_PRINT((ndo, " "));
-		if (bp[hlen] & 0x80)
-			ND_PRINT((ndo, "A"));
-		if (bp[hlen] & 0x40)
-			ND_PRINT((ndo, "H"));
-		if (bp[hlen] & 0x20)
-			ND_PRINT((ndo, "L"));
-		if (bp[hlen] & 0x10)
-			ND_PRINT((ndo, "K"));
+			if (bp[hlen] & 0x80)
+				ND_PRINT((ndo, "A"));
+			if (bp[hlen] & 0x40)
+				ND_PRINT((ndo, "H"));
+			if (bp[hlen] & 0x20)
+				ND_PRINT((ndo, "L"));
+			if (bp[hlen] & 0x10)
+				ND_PRINT((ndo, "K"));
+		}
 		/* Reserved (4bits) */
 		hlen += 1;
 		/* Reserved (8bits) */
 		hlen += 1;
-		ND_TCHECK2(*mh, hlen + 2);
+		ND_TCHECK_16BITS(&bp[hlen]);
 		/* units of 4 secs */
 		ND_PRINT((ndo, " lifetime=%u", EXTRACT_16BITS(&bp[hlen]) << 2));
 		hlen += 2;
@@ -298,14 +300,15 @@
 	case IP6M_BINDING_ACK:
 		ND_TCHECK(mh->ip6m_data8[0]);
 		ND_PRINT((ndo, " status=%u", mh->ip6m_data8[0]));
+		ND_TCHECK(mh->ip6m_data8[1]);
 		if (mh->ip6m_data8[1] & 0x80)
 			ND_PRINT((ndo, " K"));
 		/* Reserved (7bits) */
 		hlen = IP6M_MINLEN;
-		ND_TCHECK2(*mh, hlen + 2);
+		ND_TCHECK_16BITS(&bp[hlen]);
 		ND_PRINT((ndo, " seq#=%u", EXTRACT_16BITS(&bp[hlen])));
 		hlen += 2;
-		ND_TCHECK2(*mh, hlen + 2);
+		ND_TCHECK_16BITS(&bp[hlen]);
 		/* units of 4 secs */
 		ND_PRINT((ndo, " lifetime=%u", EXTRACT_16BITS(&bp[hlen]) << 2));
 		hlen += 2;
@@ -315,7 +318,7 @@
 		ND_PRINT((ndo, " status=%u", mh->ip6m_data8[0]));
 		/* Reserved */
 		hlen = IP6M_MINLEN;
-		ND_TCHECK2(*mh, hlen + 16);
+		ND_TCHECK2(bp[hlen], 16);
 		ND_PRINT((ndo, " homeaddr %s", ip6addr_string(ndo, &bp[hlen])));
 		hlen += 16;
 		break;
```
