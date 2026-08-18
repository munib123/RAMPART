# CrossVul Fix Pair: Origin Validation Error in javascript
**Pair ID:** 3144_2
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3144_2`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```javascript
Lines 1430-1470 of the vulnerable file.

                    to_resource = Strophe.getResourceFromJid(to_jid);

                if (converse.filter_by_resource && (to_resource && to_resource !== converse.resource)) {
                    converse.log(
                        'onMessage: Ignoring incoming message intended for a different resource: '+to_jid,
                        'info'
                    );
                    return true;
                } else if (utils.isHeadlineMessage(message)) {
                    // XXX: Ideally we wouldn't have to check for headline
                    // messages, but Prosody sends headline messages with the
                    // wrong type ('chat'), so we need to filter them out here.
                    converse.log(
                        "onMessage: Ignoring incoming headline message sent with type 'chat' from JID: "+from_jid,
                        'info'
                    );
                    return true;
                }
                $forwarded = $message.find('forwarded');
                if ($forwarded.length) {
                    $message = $forwarded.children('message');
                    $delay = $forwarded.children('delay');
                    from_jid = $message.attr('from');
                    to_jid = $message.attr('to');
                }
                from_bare_jid = Strophe.getBareJidFromJid(from_jid);
                from_resource = Strophe.getResourceFromJid(from_jid);
                is_me = from_bare_jid === converse.bare_jid;
                msgid = $message.attr('id');
                if (is_me) {
                    // I am the sender, so this must be a forwarded message...
                    contact_jid = Strophe.getBareJidFromJid(to_jid);
                    resource = Strophe.getResourceFromJid(to_jid);
                } else {
                    contact_jid = from_bare_jid;
                    resource = from_resource;
                }
                converse.emit('message', message);
                // Get chat box, but only create a new one when the message has a body.
                chatbox = this.getChatBox(contact_jid, $message.find('body').length > 0);
                if (!chatbox) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1447,7 +1447,14 @@
                 }
                 $forwarded = $message.find('forwarded');
                 if ($forwarded.length) {
-                    $message = $forwarded.children('message');
+                    var $forwarded_message = $forwarded.children('message');
+                    if (Strophe.getBareJidFromJid($forwarded_message.attr('from')) !== from_jid) {
+                        // Prevent message forging via carbons
+                        //
+                        // https://xmpp.org/extensions/xep-0280.html#security
+                        return true;
+                    }
+                    $message = $forwarded_message;
                     $delay = $forwarded.children('delay');
                     from_jid = $message.attr('from');
                     to_jid = $message.attr('to');
```
