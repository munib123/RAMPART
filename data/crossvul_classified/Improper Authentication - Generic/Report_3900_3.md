# CrossVul Fix Pair: Improper Authentication in javascript
**Pair ID:** 3900_3
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3900_3`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```javascript
Lines 1-37 of the vulnerable file.

'use strict';

var Class      = require('../util/class'),
    array      = require('../util/array'),
    extend     = require('../util/extend'),
    constants  = require('../util/constants'),
    Logging    = require('../mixins/logging'),
    Engine     = require('../engines/proxy'),
    Channel    = require('./channel'),
    Error      = require('./error'),
    Extensible = require('./extensible'),
    Grammar    = require('./grammar'),
    Socket     = require('./socket');

var Server = Class({ className: 'Server',
  META_METHODS: ['handshake', 'connect', 'disconnect', 'subscribe', 'unsubscribe'],

  initialize: function(options) {
    this._options  = options || {};
    var engineOpts = this._options.engine || {};
    engineOpts.timeout = this._options.timeout;
    this._engine   = Engine.get(engineOpts);

    this.info('Created new server: ?', this._options);
  },

  close: function() {
    return this._engine.close();
  },

  openSocket: function(clientId, socket, request) {
    if (!clientId || !socket) return;
    this._engine.openSocket(clientId, new Socket(this, socket, request));
  },

  closeSocket: function(clientId, close) {
    this._engine.flushConnection(clientId, close);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,8 +13,6 @@
     Socket     = require('./socket');
 
 var Server = Class({ className: 'Server',
-  META_METHODS: ['handshake', 'connect', 'disconnect', 'subscribe', 'unsubscribe'],
-
   initialize: function(options) {
     this._options  = options || {};
     var engineOpts = this._options.engine || {};
@@ -120,10 +118,10 @@
   },
 
   _handleMeta: function(message, local, callback, context) {
-    var method = Channel.parse(message.channel)[1],
+    var method = this._methodFor(message),
         response;
 
-    if (array.indexOf(this.META_METHODS, method) < 0) {
+    if (method === null) {
       response = this._makeResponse(message);
       response.error = Error.channelForbidden(message.channel);
       response.successful = false;
@@ -135,6 +133,18 @@
       for (var i = 0, n = responses.length; i < n; i++) this._advize(responses[i], message.connectionType);
       callback.call(context, responses);
     }, this);
+  },
+
+  _methodFor: function(message) {
+    var channel = message.channel;
+
+    if (channel === Channel.HANDSHAKE)   return 'handshake';
+    if (channel === Channel.CONNECT)     return 'connect';
+    if (channel === Channel.SUBSCRIBE)   return 'subscribe';
+    if (channel === Channel.UNSUBSCRIBE) return 'unsubscribe';
+    if (channel === Channel.DISCONNECT)  return 'disconnect';
+
+    return null;
   },
 
   _advize: function(response, connectionType) {
```
