# CrossVul Fix Pair: Operation on a Resource after Expiration or Release in javascript
**Pair ID:** 4203_1
**Vulnerability Class:** Operation on a Resource after Expiration or Release
**CWE:** CWE-672
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4203_1`)

## Vulnerability Information & PoC

## Description
Operation on a Resource after Expiration or Release - The product uses, accesses, or otherwise operates on a resource after that resource has been expired, released, or revoked.

## Vulnerable Code
```javascript
Lines 13-53 of the vulnerable file.

import {
  runLiveQueryEventHandlers,
  maybeRunConnectTrigger,
  maybeRunSubscribeTrigger,
  maybeRunAfterEventTrigger,
} from '../triggers';
import { getAuthForSessionToken, Auth } from '../Auth';
import { getCacheController } from '../Controllers';
import LRU from 'lru-cache';
import UserRouter from '../Routers/UsersRouter';

class ParseLiveQueryServer {
  clients: Map;
  // className -> (queryHash -> subscription)
  subscriptions: Object;
  parseWebSocketServer: Object;
  keyPairs: any;
  // The subscriber we use to get object update from publisher
  subscriber: Object;

  constructor(server: any, config: any = {}) {
    this.server = server;
    this.clients = new Map();
    this.subscriptions = new Map();

    config.appId = config.appId || Parse.applicationId;
    config.masterKey = config.masterKey || Parse.masterKey;

    // Store keys, convert obj to map
    const keyPairs = config.keyPairs || {};
    this.keyPairs = new Map();
    for (const key of Object.keys(keyPairs)) {
      this.keyPairs.set(key, keyPairs[key]);
    }
    logger.verbose('Support key pairs', this.keyPairs);

    // Initialize Parse
    Parse.Object.disableSingleInstance();
    const serverURL = config.serverURL || Parse.serverURL;
    Parse.serverURL = serverURL;
    Parse.initialize(config.appId, Parse.javaScriptKey, config.masterKey);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,10 +30,11 @@
   // The subscriber we use to get object update from publisher
   subscriber: Object;
 
-  constructor(server: any, config: any = {}) {
+  constructor(server: any, config: any = {}, parseServerConfig: any = {}) {
     this.server = server;
     this.clients = new Map();
     this.subscriptions = new Map();
+    this.config = config;
 
     config.appId = config.appId || Parse.applicationId;
     config.masterKey = config.masterKey || Parse.masterKey;
@@ -54,13 +55,15 @@
 
     // The cache controller is a proper cache controller
     // with access to User and Roles
-    this.cacheController = getCacheController(config);
+    this.cacheController = getCacheController(parseServerConfig);
+
+    config.cacheTimeout = config.cacheTimeout || 5 * 1000; // 5s
 
     // This auth cache stores the promises for each auth resolution.
     // The main benefit is to be able to reuse the same user / session token resolution.
     this.authCache = new LRU({
       max: 500, // 500 concurrent
-      maxAge: 60 * 60 * 1000, // 1h
+      maxAge: config.cacheTimeout,
     });
     // Initialize websocket server
     this.parseWebSocketServer = new ParseWebSocketServer(
@@ -510,12 +513,11 @@
         // There was an error with the session token
         const result = {};
         if (error && error.code === Parse.Error.INVALID_SESSION_TOKEN) {
-          // Store a resolved promise with the error for 10 minutes
           result.error = error;
           this.authCache.set(
             sessionToken,
             Promise.resolve(result),
-            60 * 10 * 1000
+            this.config.cacheTimeout
           );
         } else {
           this.authCache.del(sessionToken);
```
