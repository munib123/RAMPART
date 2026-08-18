# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 772_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `772_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 1-33 of the vulnerable file.

/* jshint -W097 */
/* jshint strict: false */
/* jslint node: true */
/* jshint -W061 */
'use strict';

const socketio = require('socket.io');
const request  = require('request');
const path     = require('path');
const fs       = require('fs');

function IOSocket(server, settings, adapter, objects, states, store) {
    if (!(this instanceof IOSocket)) return new IOSocket(server, settings, adapter, objects, states, store);

    const userKey = 'connect.sid'; // const
    const cmdSessions = {};
    const that = this;
    this.server = null;
    this.subscribes = {};
    let cookieParser;
    let passport;

    if (settings.auth) {
        cookieParser = require('cookie-parser');
        passport     = require('passport');
    }

    const passportSocketIo = require('passport.socketio');

    // do not send too many state updates
    const eventsThreshold = {
        count: 0,
        timeActivated: 0,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,8 +9,10 @@
 const path     = require('path');
 const fs       = require('fs');
 
-function IOSocket(server, settings, adapter, objects, states, store) {
-    if (!(this instanceof IOSocket)) return new IOSocket(server, settings, adapter, objects, states, store);
+function IOSocket(server, settings, adapter, objects, store) {
+    if (!(this instanceof IOSocket)) {
+        return new IOSocket(server, settings, adapter, objects, store);
+    }
 
     const userKey = 'connect.sid'; // const
     const cmdSessions = {};
@@ -19,6 +21,7 @@
     this.subscribes = {};
     let cookieParser;
     let passport;
+    let states = {};
 
     if (settings.auth) {
         cookieParser = require('cookie-parser');
@@ -433,10 +436,13 @@
 
     this.unsubscribe = function (socket, type, pattern) {
         //console.log((socket._name || socket.id) + ' unsubscribe ' + pattern);
-        if (!this.subscribes[type]) this.subscribes[type] = {};
+        this.subscribes[type] = this.subscribes[type] || {};
 
         if (socket) {
-            if (!socket._subscribe || !socket._subscribe[type]) return;
+            if (!socket._subscribe || !socket._subscribe[type]) {
+                return;
+            }
+
             for (let i = socket._subscribe[type].length - 1; i >= 0; i--) {
                 if (socket._subscribe[type][i].pattern === pattern) {
 
@@ -539,7 +545,7 @@
                     adapter.subscribeForeignObjects && adapter.subscribeForeignObjects(pattern);
                 } else if (type === 'log') {
                     adapter.log.debug('Subscribe LOGS');
-                    if (adapter.requireLog) adapter.requireLog(true);
+                    adapter.requireLog && adapter.requireLog(true);
                 }
             } else {
                 that.subscribes[type][pattern]++;
@@ -692,7 +698,7 @@
         socket.on('getStates', function (callback) {
             if (updateSession(socket) && checkPermissions(socket, 'getStates', callback)) {
                 if (typeof callback === 'function') {
-                    callback(null, states);
+                    adapter.getForeignStates('*', callback);
                 } else {
                     adapter.log.warn('[getStates] Invalid callback')
                 }
@@ -702,7 +708,11 @@
         socket.on('getState', function (id, callback) {
             if (updateSession(socket) && checkPermissions(socket, 'getState', callback, id)) {
                 if (typeof callback === 'function') {
-                    callback(null, states[id]);
+                    if (states[id]) {
+                        callback(null, states[id]);
+                    } else {
+                        adapter.getForeignState(id, callback);
+                    }
                 } else {
                     adapter.log.warn('[getState] Invalid callback')
                 }
@@ -711,13 +721,11 @@
 
         socket.on('getForeignStates', function (pattern, callback) {
             if (updateSession(socket) && checkPermissions(socket, 'getStates', callback)) {
-                adapter.getForeignStates(pattern, function (err, objs) {
-                    if (typeof callback === 'function') {
-                        callback(err, objs);
-                    } else {
-                        adapter.log.warn('[getForeignStates] Invalid callback')
-                    }
-                });
+                if (typeof callback === 'function') {
+                    adapter.getForeignStates(pattern, callback);
+                } else {
+                    adapter.log.warn('[getForeignStates] Invalid callback')
+                }
             }
         });
 
@@ -727,16 +735,22 @@
                     state = {val: state};
                 }
 
-                adapter.setForeignState(id, state, {user: this._acl.user}, function (err, res) {
-                    if (typeof callback === 'function') {
-                        callback(err, res);
-                    }
-                });
+                // clear cache
+                if (states[id]) {
+                    delete states[id];
+                }
+
+                adapter.setForeignState(id, state, {user: this._acl.user}, (err, res) =>
+                    typeof callback === 'function' && callback(err, res));
             }
         });
 
         socket.on('delState', function (id, callback) {
             if (updateSession(socket) && checkPermissions(socket, 'delState', callback, id)) {
+                // clear cache
+                if (states[id]) {
+                    delete states[id];
+                }
                 adapter.delForeignState(id, {user: this._acl.user}, callback);
             }
         });
@@ -965,7 +979,6 @@
             }
         });
 
-
         socket.on('unsubscribe', function (pattern, callback) {
             if (updateSession(socket) && checkPermissions(socket, 'unsubscribe', callback, pattern)) {
                 if (pattern && typeof pattern === 'object' && pattern instanceof Array) {
@@ -975,10 +988,13 @@
                 } else {
                     that.unsubscribe(this, 'stateChange', pattern);
                 }
-                if (adapter.log.level === 'debug') showSubscribes(socket, 'stateChange');
-                if (typeof callback === 'function') {
-                    setImmediate(callback, null);
-                }
+
+                // reset states cache on unsubscribe
+                states = {};
+
+                adapter.log.level === 'debug' && showSubscribes(socket, 'stateChange');
+
+                typeof callback === 'function' && setImmediate(callback, null);
             }
         });
 
@@ -1168,7 +1184,7 @@
             adapter.log.info('Subscribe on all states again');
 
             setTimeout(function () {
-                if (readAll) {
+                /*if (readAll) {
                     adapter.getForeignStates('*', function (err, res) {
                         adapter.log.info('received all states');
                         for (const id in res) {
@@ -1178,11 +1194,14 @@
                             }
                         }
                     });
-                }
+                }*/
 
                 that.server.sockets.emit('eventsThreshold', false);
                 adapter.unsubscribeForeignStates('system.adapter.*');
-                adapter.subscribeForeignStates('*');
+
+                Object.keys(that.subscribes.stateChange).forEach(pattern =>
+                    adapter.subscribeForeignStates(pattern));
+
             }, 50);
         }
     }
@@ -1196,7 +1215,10 @@
                 eventsThreshold.timeActivated = new Date().getTime();
 
                 that.server.sockets.emit('eventsThreshold', true);
-                adapter.unsubscribeForeignStates('*');
+
+                Object.keys(that.subscribes.stateChange).forEach(pattern =>
+                    adapter.unsubscribeForeignStates(pattern));
+
                 adapter.subscribeForeignStates('system.adapter.*');
             }, 100);
         }
@@ -1240,6 +1262,13 @@
     };
 
     this.stateChange = function (id, state) {
+        if (!state) {
+            if (states[id]) {
+                delete states[id];
+            }
+        } else {
+            states[id] = state;
+        }
         const clients = that.server.sockets.connected;
 
         if (!eventsThreshold.active) {
@@ -1309,4 +1338,5 @@
 
     return this;
 }
+
 module.exports = IOSocket;
```
