# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in java
**Pair ID:** 4768_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4768_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```java
Lines 345-385 of the vulnerable file.

     * Listeners will be preserved from a previous connection.
     * 
     * @throws XMPPException if an error occurs on the XMPP protocol level.
     * @throws SmackException if an error occurs somewhere else besides XMPP protocol level.
     * @throws IOException 
     * @throws ConnectionException with detailed information about the failed connection.
     * @return a reference to this object, to chain <code>connect()</code> with <code>login()</code>.
     */
    public synchronized AbstractXMPPConnection connect() throws SmackException, IOException, XMPPException {
        // Check if not already connected
        throwAlreadyConnectedExceptionIfAppropriate();

        // Reset the connection state
        saslAuthentication.init();
        saslFeatureReceived.init();
        lastFeaturesReceived.init();
        streamId = null;

        // Perform the actual connection to the XMPP service
        connectInternal();
        return this;
    }

    /**
     * Abstract method that concrete subclasses of XMPPConnection need to implement to perform their
     * way of XMPP connection establishment. Implementations are required to perform an automatic
     * login if the previous connection state was logged (authenticated).
     * 
     * @throws SmackException
     * @throws IOException
     * @throws XMPPException
     */
    protected abstract void connectInternal() throws SmackException, IOException, XMPPException;

    private String usedUsername, usedPassword, usedResource;

    /**
     * Logs in to the server using the strongest SASL mechanism supported by
     * the server. If more than the connection's default stanza(/packet) timeout elapses in each step of the 
     * authentication process without a response from the server, a
     * {@link SmackException.NoResponseException} will be thrown.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -362,6 +362,7 @@
 
         // Perform the actual connection to the XMPP service
         connectInternal();
+
         return this;
     }
 
```
