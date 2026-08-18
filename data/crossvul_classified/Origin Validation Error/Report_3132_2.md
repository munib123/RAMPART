# CrossVul Fix Pair: Origin Validation Error in javascript
**Pair ID:** 3132_2
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3132_2`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```javascript
Lines 110-150 of the vulnerable file.

    self.has = function() {

        try {
            return Features.enabledCarbons();
        } catch(e) {
            Console.error('Carbons.has', e);
        }

    };


    /**
     * Returns the forwarded message stanza
     * @public
     * @param {object} message
     * @return {object}
     */
    self._getForwarded = function(message) {

        try {
            var forwarded_message = $(message.getNode()).find('forwarded[xmlns="' + NS_URN_FORWARD + '"]:first message:first');

            if(forwarded_message[0]) {
                return JSJaCPacket.wrapNode(forwarded_message[0]);
            }

            return null;
        } catch(e) {
            Console.error('Carbons._getForwarded', e);
        }

    };


    /**
     * Handles a forwarded sent message
     * @public
     * @param {object} message
     * @return {undefined}
     */
    self.handleSent = function(message) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -127,10 +127,13 @@
     self._getForwarded = function(message) {
 
         try {
-            var forwarded_message = $(message.getNode()).find('forwarded[xmlns="' + NS_URN_FORWARD + '"]:first message:first');
-
-            if(forwarded_message[0]) {
-                return JSJaCPacket.wrapNode(forwarded_message[0]);
+            // Check message is forwarded from our local user
+            if(Common.bareXID(Common.getStanzaFrom(message)) == Common.getXID()) {
+                var forwarded_message = $(message.getNode()).find('forwarded[xmlns="' + NS_URN_FORWARD + '"]:first message:first');
+
+                if(forwarded_message[0]) {
+                    return JSJaCPacket.wrapNode(forwarded_message[0]);
+                }
             }
 
             return null;
```
