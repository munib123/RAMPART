# CrossVul Fix Pair: Origin Validation Error in python
**Pair ID:** 3126_0
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3126_0`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```python
Lines 44-84 of the vulnerable file.

        register_stanza_plugin(Message, stanza.ReceivedCarbon)
        register_stanza_plugin(Message, stanza.SentCarbon)
        register_stanza_plugin(Message, stanza.PrivateCarbon)
        register_stanza_plugin(Iq, stanza.CarbonEnable)
        register_stanza_plugin(Iq, stanza.CarbonDisable)

        register_stanza_plugin(stanza.ReceivedCarbon,
                               self.xmpp['xep_0297'].stanza.Forwarded)
        register_stanza_plugin(stanza.SentCarbon,
                               self.xmpp['xep_0297'].stanza.Forwarded)

    def plugin_end(self):
        self.xmpp.remove_handler('Carbon Received')
        self.xmpp.remove_handler('Carbon Sent')
        self.xmpp.plugin['xep_0030'].del_feature(feature='urn:xmpp:carbons:2')

    def session_bind(self, jid):
        self.xmpp.plugin['xep_0030'].add_feature('urn:xmpp:carbons:2')

    def _handle_carbon_received(self, msg):
        self.xmpp.event('carbon_received', msg)

    def _handle_carbon_sent(self, msg):
        self.xmpp.event('carbon_sent', msg)

    def enable(self, ifrom=None, timeout=None, callback=None,
               timeout_callback=None):
        iq = self.xmpp.Iq()
        iq['type'] = 'set'
        iq['from'] = ifrom
        iq.enable('carbon_enable')
        return iq.send(timeout_callback=timeout_callback, timeout=timeout,
                       callback=callback)

    def disable(self, ifrom=None, timeout=None, callback=None,
                timeout_callback=None):
        iq = self.xmpp.Iq()
        iq['type'] = 'set'
        iq['from'] = ifrom
        iq.enable('carbon_disable')
        return iq.send(timeout_callback=timeout_callback, timeout=timeout,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,10 +61,12 @@
         self.xmpp.plugin['xep_0030'].add_feature('urn:xmpp:carbons:2')
 
     def _handle_carbon_received(self, msg):
-        self.xmpp.event('carbon_received', msg)
+        if msg['from'].bare == self.xmpp.boundjid.bare:
+            self.xmpp.event('carbon_received', msg)
 
     def _handle_carbon_sent(self, msg):
-        self.xmpp.event('carbon_sent', msg)
+        if msg['from'].bare == self.xmpp.boundjid.bare:
+            self.xmpp.event('carbon_sent', msg)
 
     def enable(self, ifrom=None, timeout=None, callback=None,
                timeout_callback=None):
```
