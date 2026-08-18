# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 3258_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3258_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 9-49 of the vulnerable file.

 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */
//
// CConnection - class on the client side representing a connection to a
// server.  A derived class should override methods appropriately.
//

#ifndef __RFB_CCONNECTION_H__
#define __RFB_CCONNECTION_H__

#include <rfb/CMsgHandler.h>
#include <rfb/DecodeManager.h>
#include <rfb/util.h>

namespace rfb {

  class CMsgReader;
  class CMsgWriter;
  class CSecurity;
  class IdentityVerifier;
  class SecurityClient;

  class CConnection : public CMsgHandler {
  public:

    CConnection();
    virtual ~CConnection();

    // Methods to initialise the connection

    // setServerName() is used to provide a unique(ish) name for the server to
    // which we are connected.  This might be the result of getPeerEndpoint on
    // a TcpSocket, for example, or a host specified by DNS name & port.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,7 @@
 
 #include <rfb/CMsgHandler.h>
 #include <rfb/DecodeManager.h>
+#include <rfb/SecurityClient.h>
 #include <rfb/util.h>
 
 namespace rfb {
@@ -34,7 +35,6 @@
   class CMsgWriter;
   class CSecurity;
   class IdentityVerifier;
-  class SecurityClient;
 
   class CConnection : public CMsgHandler {
   public:
@@ -148,7 +148,7 @@
     stateEnum state() { return state_; }
 
     CSecurity *csecurity;
-    SecurityClient *security;
+    SecurityClient security;
   protected:
     void setState(stateEnum s) { state_ = s; }
 
```
