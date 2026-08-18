# CrossVul Fix Pair: Improper Certificate Validation in c
**Pair ID:** 4600_3
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4600_3`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```c
Lines 12-52 of the vulnerable file.

 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give permission
 *  to link the code of portions of this program with the OpenSSL library under
 *  certain conditions as described in each individual source file, and
 *  distribute linked combinations including the two.
 *  You must obey the GNU General Public License in all respects for all of the
 *  code used other than OpenSSL.  If you modify file(s) with this exception,
 *  you may extend this exception to your version of the file(s), but you are
 *  not obligated to do so.  If you do not wish to do so, delete this exception
 *  statement from your version.  If you delete this exception statement from
 *  all source files in the program, then also delete it here.
 */

#include "tunnel.h"
#include "http.h"
#include "log.h"

#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#if HAVE_PTY_H
#include <pty.h>
#elif HAVE_UTIL_H
#include <util.h>
#endif
#include <termios.h>
#include <signal.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,9 @@
 #include "tunnel.h"
 #include "http.h"
 #include "log.h"
+#ifndef HAVE_X509_CHECK_HOST
+#include "openssl_hostname_validation.h"
+#endif
 
 #include <unistd.h>
 #include <fcntl.h>
@@ -671,15 +674,10 @@
 	                    0, 0, NULL) == 1)
 		cert_valid = 1;
 #else
-	char common_name[FIELD_SIZE + 1];
-	// Use explicit Common Name check if native validation not available.
-	// Note: this will ignore Subject Alternative Name fields.
-	if (subj
-	    && X509_NAME_get_text_by_NID(subj, NID_commonName, common_name,
-	                                 FIELD_SIZE) > 0
-	    && strncasecmp(common_name, tunnel->config->gateway_host,
-	                   FIELD_SIZE) == 0)
-		cert_valid = 1;
+	// Use validate_hostname form iSECPartners if native validation not available
+	// in order to avoid TLS Certificate CommonName NULL Byte Vulnerability
+	if (validate_hostname(tunnel->config->gateway_host, cert) == MatchFound)
+ 		cert_valid = 1;
 #endif
 
 	// Try to validate certificate using local PKI
```
