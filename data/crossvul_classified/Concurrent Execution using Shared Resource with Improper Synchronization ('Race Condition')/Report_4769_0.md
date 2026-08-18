# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in java
**Pair ID:** 4769_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4769_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```java
Lines 29-69 of the vulnerable file.

import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jivesoftware.smack.ConnectionConfiguration.SecurityMode;
import org.jivesoftware.smack.SmackException.AlreadyConnectedException;
import org.jivesoftware.smack.SmackException.AlreadyLoggedInException;
import org.jivesoftware.smack.SmackException.NoResponseException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.SmackException.ResourceBindingNotOfferedException;
import org.jivesoftware.smack.SmackException.SecurityRequiredException;
import org.jivesoftware.smack.XMPPException.StreamErrorException;
import org.jivesoftware.smack.XMPPException.XMPPErrorException;
import org.jivesoftware.smack.compress.packet.Compress;
import org.jivesoftware.smack.compression.XMPPInputOutputStream;
import org.jivesoftware.smack.debugger.SmackDebugger;
import org.jivesoftware.smack.filter.IQReplyFilter;
import org.jivesoftware.smack.filter.StanzaFilter;
import org.jivesoftware.smack.filter.StanzaIdFilter;
import org.jivesoftware.smack.iqrequest.IQRequestHandler;
import org.jivesoftware.smack.packet.Bind;
import org.jivesoftware.smack.packet.ErrorIQ;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Mechanisms;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.Session;
import org.jivesoftware.smack.packet.StartTls;
import org.jivesoftware.smack.packet.Nonza;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,6 +46,7 @@
 import org.jivesoftware.smack.SmackException.NoResponseException;
 import org.jivesoftware.smack.SmackException.NotConnectedException;
 import org.jivesoftware.smack.SmackException.ResourceBindingNotOfferedException;
+import org.jivesoftware.smack.SmackException.SecurityRequiredByClientException;
 import org.jivesoftware.smack.SmackException.SecurityRequiredException;
 import org.jivesoftware.smack.XMPPException.StreamErrorException;
 import org.jivesoftware.smack.XMPPException.XMPPErrorException;
@@ -372,6 +373,13 @@
 
         // Wait with SASL auth until the SASL mechanisms have been received
         saslFeatureReceived.checkIfSuccessOrWaitOrThrow();
+
+        // If TLS is required but the server doesn't offer it, disconnect
+        // from the server and throw an error. First check if we've already negotiated TLS
+        // and are secure, however (features get parsed a second time after TLS is established).
+        if (!isSecureConnection() && getConfiguration().getSecurityMode() == SecurityMode.required) {
+            throw new SecurityRequiredByClientException();
+        }
 
         // Make note of the fact that we're now connected.
         connected = true;
```
