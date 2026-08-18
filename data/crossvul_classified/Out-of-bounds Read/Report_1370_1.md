# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1370_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1370_1`)

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
__FBSDID("$FreeBSD: head/sys/netinet/sctp_pcb.c 353477 2019-10-13 16:14:04Z markj $");
#endif

#include <netinet/sctp_os.h>
#ifdef __FreeBSD__
#include <sys/proc.h>
#endif
#include <netinet/sctp_var.h>
#include <netinet/sctp_sysctl.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctputil.h>
#include <netinet/sctp.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_timer.h>
#include <netinet/sctp_bsd_addr.h>
#if defined(INET) || defined(INET6)
#if !defined(__Userspace_os_Windows)
#include <netinet/udp.h>
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,7 +34,7 @@
 
 #ifdef __FreeBSD__
 #include <sys/cdefs.h>
-__FBSDID("$FreeBSD: head/sys/netinet/sctp_pcb.c 353477 2019-10-13 16:14:04Z markj $");
+__FBSDID("$FreeBSD: head/sys/netinet/sctp_pcb.c 355931 2019-12-20 15:25:08Z tuexen $");
 #endif
 
 #include <netinet/sctp_os.h>
@@ -7247,7 +7247,7 @@
 		if (offset + plen > limit) {
 			break;
 		}
-		if (plen == 0) {
+		if (plen < sizeof(struct sctp_paramhdr)) {
 			break;
 		}
 #ifdef INET
@@ -7463,6 +7463,9 @@
 			if (plen > sizeof(lstore)) {
 				return (-23);
 			}
+			if (plen < sizeof(struct sctp_asconf_addrv4_param)) {
+				return (-101);
+			}
 			phdr = sctp_get_next_param(m, offset,
 						   (struct sctp_paramhdr *)&lstore,
 						   plen);
```
