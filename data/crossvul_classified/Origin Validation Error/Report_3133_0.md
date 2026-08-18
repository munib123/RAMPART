# CrossVul Fix Pair: Origin Validation Error in java
**Pair ID:** 3133_0
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3133_0`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```java
Lines 798-838 of the vulnerable file.

                (org.jivesoftware.smack.packet.Message)packet;

            boolean isForwardedSentMessage = false;
            if(msg.getBody() == null)
            {

                CarbonPacketExtension carbonExt
                    = (CarbonPacketExtension) msg.getExtension(
                        CarbonPacketExtension.NAMESPACE);
                if(carbonExt == null)
                    return;

                isForwardedSentMessage
                    = (carbonExt.getElementName()
                        == CarbonPacketExtension.SENT_ELEMENT_NAME);
                List<ForwardedPacketExtension> extensions
                    = carbonExt.getChildExtensionsOfType(
                        ForwardedPacketExtension.class);
                if(extensions.isEmpty())
                    return;
                ForwardedPacketExtension forwardedExt = extensions.get(0);
                msg = forwardedExt.getMessage();
                if(msg == null || msg.getBody() == null)
                    return;

            }

            Object multiChatExtension =
                msg.getExtension("x", "http://jabber.org/protocol/muc#user");

            // its not for us
            if(multiChatExtension != null)
                return;

            String userFullId
                = isForwardedSentMessage? msg.getTo() : msg.getFrom();

            String userBareID = StringUtils.parseBareAddress(userFullId);

            boolean isPrivateMessaging = false;
            ChatRoom privateContactRoom = null;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -815,6 +815,17 @@
                         ForwardedPacketExtension.class);
                 if(extensions.isEmpty())
                     return;
+
+                // according to xep-0280 all carbons should come from
+                // our bare jid
+                if (!msg.getFrom().equals(
+                        StringUtils.parseBareAddress(
+                            jabberProvider.getOurJID())))
+                {
+                    logger.info("Received a carbon copy with wrong from!");
+                    return;
+                }
+
                 ForwardedPacketExtension forwardedExt = extensions.get(0);
                 msg = forwardedExt.getMessage();
                 if(msg == null || msg.getBody() == null)
```
