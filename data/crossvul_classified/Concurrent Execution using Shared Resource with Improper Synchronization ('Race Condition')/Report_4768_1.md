# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in java
**Pair ID:** 4768_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4768_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```java
Lines 11-51 of the vulnerable file.

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.smack.tcp;

import org.jivesoftware.smack.AbstractConnectionListener;
import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.ConnectionConfiguration.SecurityMode;
import org.jivesoftware.smack.ConnectionCreationListener;
import org.jivesoftware.smack.StanzaListener;
import org.jivesoftware.smack.SmackConfiguration;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.SmackException.AlreadyConnectedException;
import org.jivesoftware.smack.SmackException.AlreadyLoggedInException;
import org.jivesoftware.smack.SmackException.NoResponseException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.SmackException.ConnectionException;
import org.jivesoftware.smack.SmackException.SecurityRequiredByClientException;
import org.jivesoftware.smack.SmackException.SecurityRequiredByServerException;
import org.jivesoftware.smack.SmackException.SecurityRequiredException;
import org.jivesoftware.smack.SynchronizationPoint;
import org.jivesoftware.smack.XMPPException.StreamErrorException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.XMPPException.XMPPErrorException;
import org.jivesoftware.smack.compress.packet.Compressed;
import org.jivesoftware.smack.compression.XMPPInputOutputStream;
import org.jivesoftware.smack.filter.StanzaFilter;
import org.jivesoftware.smack.compress.packet.Compress;
import org.jivesoftware.smack.packet.Element;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.StreamOpen;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.StartTls;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,10 +28,9 @@
 import org.jivesoftware.smack.SmackException.AlreadyLoggedInException;
 import org.jivesoftware.smack.SmackException.NoResponseException;
 import org.jivesoftware.smack.SmackException.NotConnectedException;
+import org.jivesoftware.smack.SmackException.SecurityRequiredByClientException;
 import org.jivesoftware.smack.SmackException.ConnectionException;
-import org.jivesoftware.smack.SmackException.SecurityRequiredByClientException;
 import org.jivesoftware.smack.SmackException.SecurityRequiredByServerException;
-import org.jivesoftware.smack.SmackException.SecurityRequiredException;
 import org.jivesoftware.smack.SynchronizationPoint;
 import org.jivesoftware.smack.XMPPException.StreamErrorException;
 import org.jivesoftware.smack.XMPPConnection;
@@ -857,6 +856,14 @@
         // Wait with SASL auth until the SASL mechanisms have been received
         saslFeatureReceived.checkIfSuccessOrWaitOrThrow();
 
+        // If TLS is required but the server doesn't offer it, disconnect
+        // from the server and throw an error. First check if we've already negotiated TLS
+        // and are secure, however (features get parsed a second time after TLS is established).
+        if (!isSecureConnection() && getConfiguration().getSecurityMode() == SecurityMode.required) {
+            shutdown();
+            throw new SecurityRequiredByClientException();
+        }
+
         // Make note of the fact that we're now connected.
         connected = true;
         callConnectionConnectedListener();
@@ -897,7 +904,7 @@
     }
 
     @Override
-    protected void afterFeaturesReceived() throws SecurityRequiredException, NotConnectedException {
+    protected void afterFeaturesReceived() throws NotConnectedException {
         StartTls startTlsFeature = getFeature(StartTls.ELEMENT, StartTls.NAMESPACE);
         if (startTlsFeature != null) {
             if (startTlsFeature.required() && config.getSecurityMode() == SecurityMode.disabled) {
@@ -908,13 +915,6 @@
             if (config.getSecurityMode() != ConnectionConfiguration.SecurityMode.disabled) {
                 send(new StartTls());
             }
-        }
-        // If TLS is required but the server doesn't offer it, disconnect
-        // from the server and throw an error. First check if we've already negotiated TLS
-        // and are secure, however (features get parsed a second time after TLS is established).
-        if (!isSecureConnection() && startTlsFeature == null
-                        && getConfiguration().getSecurityMode() == SecurityMode.required) {
-            throw new SecurityRequiredByClientException();
         }
 
         if (getSASLAuthentication().authenticationSuccessful()) {
```
