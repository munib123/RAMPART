# CrossVul Fix Pair: Origin Validation Error in javascript
**Pair ID:** 3144_1
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3144_1`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```javascript
Lines 749-789 of the vulnerable file.

                    )).toBeTruthy();
                    expect(utils.isHeadlineMessage.called).toBeTruthy();
                    expect(utils.isHeadlineMessage.returned(true)).toBeTruthy();
                    expect(converse.chatboxes.getChatBox.called).toBeFalsy();
                    // Remove sinon spies
                    converse.log.restore();
                    converse.chatboxes.getChatBox.restore();
                    utils.isHeadlineMessage.restore();
                }));

                it("can be a carbon message, as defined in XEP-0280", mock.initConverse(function (converse) {
                    test_utils.createContacts(converse, 'current');
                    test_utils.openControlBox();
                    test_utils.openContactsPanel(converse);

                    // Send a message from a different resource
                    spyOn(converse, 'log');
                    var msgtext = 'This is a carbon message';
                    var sender_jid = mock.cur_names[1].replace(/ /g,'.').toLowerCase() + '@localhost';
                    var msg = $msg({
                            'from': converse.bare_jid,
                            'id': (new Date()).getTime(),
                            'to': converse.connection.jid,
                            'type': 'chat',
                            'xmlns': 'jabber:client'
                        }).c('received', {'xmlns': 'urn:xmpp:carbons:2'})
                          .c('forwarded', {'xmlns': 'urn:xmpp:forward:0'})
                          .c('message', {
                                'xmlns': 'jabber:client',
                                'from': sender_jid,
                                'to': converse.bare_jid+'/another-resource',
                                'type': 'chat'
                        }).c('body').t(msgtext).tree();
                    converse.chatboxes.onMessage(msg);

                    // Check that the chatbox and its view now exist
                    var chatbox = converse.chatboxes.get(sender_jid);
                    var chatboxview = converse.chatboxviews.get(sender_jid);
                    expect(chatbox).toBeDefined();
                    expect(chatboxview).toBeDefined();
                    // Check that the message was received and check the message parameters
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -766,7 +766,7 @@
                     var msgtext = 'This is a carbon message';
                     var sender_jid = mock.cur_names[1].replace(/ /g,'.').toLowerCase() + '@localhost';
                     var msg = $msg({
-                            'from': converse.bare_jid,
+                            'from': sender_jid,
                             'id': (new Date()).getTime(),
                             'to': converse.connection.jid,
                             'type': 'chat',
@@ -842,6 +842,49 @@
                     var $chat_content = chatboxview.$el.find('.chat-content');
                     var msg_txt = $chat_content.find('.chat-message').find('.chat-msg-content').text();
                     expect(msg_txt).toEqual(msgtext);
+                }));
+
+                it("will be discarded if it's a malicious message meant to look like a carbon copy", mock.initConverse(function (converse) {
+                    test_utils.createContacts(converse, 'current');
+                    test_utils.openControlBox();
+                    test_utils.openContactsPanel(converse);
+                    /* <message from="mallory@evil.example" to="b@xmpp.example">
+                     *    <received xmlns='urn:xmpp:carbons:2'>
+                     *      <forwarded xmlns='urn:xmpp:forward:0'>
+                     *          <message from="alice@xmpp.example" to="bob@xmpp.example/client1">
+                     *              <body>Please come to Creepy Valley tonight, alone!</body>
+                     *          </message>
+                     *      </forwarded>
+                     *    </received>
+                     * </message>
+                     */
+                    spyOn(converse, 'log');
+                    var msgtext = 'Please come to Creepy Valley tonight, alone!';
+                    var sender_jid = mock.cur_names[1].replace(/ /g,'.').toLowerCase() + '@localhost';
+                    var impersonated_jid = mock.cur_names[2].replace(/ /g,'.').toLowerCase() + '@localhost';
+                    var msg = $msg({
+                            'from': sender_jid,
+                            'id': (new Date()).getTime(),
+                            'to': converse.connection.jid,
+                            'type': 'chat',
+                            'xmlns': 'jabber:client'
+                        }).c('received', {'xmlns': 'urn:xmpp:carbons:2'})
+                          .c('forwarded', {'xmlns': 'urn:xmpp:forward:0'})
+                          .c('message', {
+                                'xmlns': 'jabber:client',
+                                'from': impersonated_jid,
+                                'to': converse.connection.jid,
+                                'type': 'chat'
+                        }).c('body').t(msgtext).tree();
+                    converse.chatboxes.onMessage(msg);
+
+                    // Check that chatbox for impersonated user is not created.
+                    var chatbox = converse.chatboxes.get(impersonated_jid);
+                    expect(chatbox).not.toBeDefined();
+
+                    // Check that the chatbox for the malicous user is not created
+                    chatbox = converse.chatboxes.get(sender_jid);
+                    expect(chatbox).not.toBeDefined();
                 }));
 
                 it("received for a minimized chat box will increment a counter on its header", mock.initConverse(function (converse) {
```
