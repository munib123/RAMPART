# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 2112_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2112_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 136-176 of the vulnerable file.

    case CONN_STATE_SELECTED:
    case CONN_STATE_FETCHING_PART:
    case CONN_STATE_FETCHING_MSG_METADATA:
    case CONN_STATE_LOGOUT:
    {
        QByteArray message = "No response expected by the OpenConnectionTask in state " +
                Imap::connectionStateToString(model->accessParser(parser).connState).toUtf8();
        // These shall not ever be reached by this code
        throw Imap::UnexpectedResponseReceived(message.constData(), *resp);
    }

    case CONN_STATE_NONE:
    case CONN_STATE_HOST_LOOKUP:
    case CONN_STATE_CONNECTING:
        // Looks like the corresponding stateChanged() signal could be delayed, at least with QProcess-based sockets
    case CONN_STATE_CONNECTED_PRETLS_PRECAPS:
        // We're connected now -- this is our initial state.
    {
        switch (resp->kind) {
        case PREAUTH:
            // Cool, we're already authenticated. Now, let's see if we have to issue CAPABILITY or if we already know that
            if (model->accessParser(parser).capabilitiesFresh) {
                // We're alsmost done here, apart from compression
                if (TROJITA_COMPRESS_DEFLATE && model->accessParser(parser).capabilities.contains(QLatin1String("COMPRESS=DEFLATE"))) {
                    compressCmd = parser->compressDeflate();
                    model->changeConnectionState(parser, CONN_STATE_COMPRESS_DEFLATE);
                } else {
                    // really done
                    model->changeConnectionState(parser, CONN_STATE_AUTHENTICATED);
                    onComplete();
                }
            } else {
                model->changeConnectionState(parser, CONN_STATE_POSTAUTH_PRECAPS);
                capabilityCmd = parser->capability();
            }
            return true;

        case OK:
            if (!model->accessParser(parser).capabilitiesFresh) {
                model->changeConnectionState(parser, CONN_STATE_CONNECTED_PRETLS);
                capabilityCmd = parser->capability();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -153,6 +153,17 @@
     {
         switch (resp->kind) {
         case PREAUTH:
+            if (model->m_startTls) {
+                // Oops, we cannot send STARTTLS when the connection is already authenticated.
+                // This is serious enough to warrant an error; an attacker might be going after a plaintext
+                // of a message we're going to APPEND, etc.
+                // Thanks to Arnt Gulbrandsen on the imap-protocol ML for asking what happens when we're configured
+                // to request STARTTLS and a PREAUTH is received, and to Michael M Slusarz for starting that discussion.
+                logout(tr("Configuration requires sending STARTTLS, but the IMAP server greets us with PREAUTH. "
+                          "Encryption cannot be established. If this configuration worked previously, someone "
+                          "is after your data and they are pretty smart."));
+                return true;
+            }
             // Cool, we're already authenticated. Now, let's see if we have to issue CAPABILITY or if we already know that
             if (model->accessParser(parser).capabilitiesFresh) {
                 // We're alsmost done here, apart from compression
```
