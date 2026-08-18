# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2677_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2677_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.

 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: Ad hoc On-Demand Distance Vector (AODV) Routing printer */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"


struct aodv_rreq {
	uint8_t		rreq_type;	/* AODV message type (1) */
	uint8_t		rreq_flags;	/* various flags */
	uint8_t		rreq_zero0;	/* reserved, set to zero */
	uint8_t		rreq_hops;	/* number of hops from originator */
	uint32_t	rreq_id;	/* request ID */
	uint32_t	rreq_da;	/* destination IPv4 address */
	uint32_t	rreq_ds;	/* destination sequence number */
	uint32_t	rreq_oa;	/* originator IPv4 address */
	uint32_t	rreq_os;	/* originator sequence number */
};
struct aodv_rreq6 {
	uint8_t		rreq_type;	/* AODV message type (1) */
	uint8_t		rreq_flags;	/* various flags */
	uint8_t		rreq_zero0;	/* reserved, set to zero */
	uint8_t		rreq_hops;	/* number of hops from originator */
	uint32_t	rreq_id;	/* request ID */
	struct in6_addr	rreq_da;	/* destination IPv6 address */
	uint32_t	rreq_ds;	/* destination sequence number */
	struct in6_addr	rreq_oa;	/* originator IPv6 address */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,7 +42,9 @@
 #include "addrtoname.h"
 #include "extract.h"
 
-
+/*
+ * RFC 3561
+ */
 struct aodv_rreq {
 	uint8_t		rreq_type;	/* AODV message type (1) */
 	uint8_t		rreq_flags;	/* various flags */
@@ -178,12 +180,17 @@
 {
 	const struct aodv_hello *ah;
 
+	ND_TCHECK(*ep);
 	switch (ep->type) {
 	case AODV_EXT_HELLO:
 		ah = (const struct aodv_hello *)(const void *)ep;
 		ND_TCHECK(*ah);
 		if (length < sizeof(struct aodv_hello))
 			goto trunc;
+		if (ep->length < 4) {
+			ND_PRINT((ndo, "\n\text HELLO - bad length %u", ep->length));
+			break;
+		}
 		ND_PRINT((ndo, "\n\text HELLO %ld ms",
 		    (unsigned long)EXTRACT_32BITS(&ah->interval)));
 		break;
```
