# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1370_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1370_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 17-57 of the vulnerable file.

 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef __FreeBSD__
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/sys/netinet/sctp_auth.c 352438 2019-09-17 09:46:42Z tuexen $");
#endif

#include <netinet/sctp_os.h>
#include <netinet/sctp.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_sysctl.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_indata.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_auth.h>

#ifdef SCTP_DEBUG
#define SCTP_AUTH_DEBUG		(SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_AUTH1)
#define SCTP_AUTH_DEBUG2	(SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_AUTH2)
#endif /* SCTP_DEBUG */


void
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,7 +34,7 @@
 
 #ifdef __FreeBSD__
 #include <sys/cdefs.h>
-__FBSDID("$FreeBSD: head/sys/netinet/sctp_auth.c 352438 2019-09-17 09:46:42Z tuexen $");
+__FBSDID("$FreeBSD: head/sys/netinet/sctp_auth.c 355931 2019-12-20 15:25:08Z tuexen $");
 #endif
 
 #include <netinet/sctp_os.h>
@@ -1421,7 +1421,8 @@
 		ptype = ntohs(phdr->param_type);
 		plen = ntohs(phdr->param_length);
 
-		if ((plen == 0) || (offset + plen > length))
+		if ((plen < sizeof(struct sctp_paramhdr)) ||
+		    (offset + plen > length))
 			break;
 
 		if (ptype == SCTP_RANDOM) {
```
