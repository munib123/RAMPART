# CrossVul Fix Pair: Operation on a Resource after Expiration or Release in javascript
**Pair ID:** 4203_3
**Vulnerability Class:** Operation on a Resource after Expiration or Release
**CWE:** CWE-672
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4203_3`)

## Vulnerability Information & PoC

## Description
Operation on a Resource after Expiration or Release - The product uses, accesses, or otherwise operates on a resource after that resource has been expired, released, or revoked.

## Vulnerable Code
```javascript
Lines 83-120 of the vulnerable file.

 * @property {String} invalidVerificationLink invalid verification link page path
 * @property {String} linkSendFail verification link send fail page path
 * @property {String} linkSendSuccess verification link send success page path
 * @property {String} parseFrameURL for masking user-facing pages
 * @property {String} passwordResetSuccess password reset success page path
 * @property {String} verifyEmailSuccess verify email success page path
 */

/**
 * @interface LiveQueryOptions
 * @property {String[]} classNames parse-server's LiveQuery classNames
 * @property {Adapter<PubSubAdapter>} pubSubAdapter LiveQuery pubsub adapter
 * @property {Any} redisOptions parse-server's LiveQuery redisOptions
 * @property {String} redisURL parse-server's LiveQuery redisURL
 * @property {Adapter<WSSAdapter>} wssAdapter Adapter module for the WebSocketServer
 */

/**
 * @interface LiveQueryServerOptions
 * @property {String} appId This string should match the appId in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same appId.
 * @property {Number} cacheTimeout Number in milliseconds. When clients provide the sessionToken to the LiveQuery server, the LiveQuery server will try to fetch its ParseUser's objectId from parse server and store it in the cache. The value defines the duration of the cache. Check the following Security section and our protocol specification for details, defaults to 30 * 24 * 60 * 60 * 1000 ms (~30 days).
 * @property {Any} keyPairs A JSON object that serves as a whitelist of keys. It is used for validating clients when they try to connect to the LiveQuery server. Check the following Security section and our protocol specification for details.
 * @property {String} logLevel This string defines the log level of the LiveQuery server. We support VERBOSE, INFO, ERROR, NONE, defaults to INFO.
 * @property {String} masterKey This string should match the masterKey in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same masterKey.
 * @property {Number} port The port to run the LiveQuery server, defaults to 1337.
 * @property {Adapter<PubSubAdapter>} pubSubAdapter LiveQuery pubsub adapter
 * @property {Any} redisOptions parse-server's LiveQuery redisOptions
 * @property {String} redisURL parse-server's LiveQuery redisURL
 * @property {String} serverURL This string should match the serverURL in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same serverURL.
 * @property {Number} websocketTimeout Number of milliseconds between ping/pong frames. The WebSocket server sends ping/pong frames to the clients to keep the WebSocket alive. This value defines the interval of the ping/pong frame from the server to clients, defaults to 10 * 1000 ms (10 s).
 * @property {Adapter<WSSAdapter>} wssAdapter Adapter module for the WebSocketServer
 */

/**
 * @interface IdempotencyOptions
 * @property {String[]} paths An array of paths for which the feature should be enabled. The mount path must not be included, for example instead of `/parse/functions/myFunction` specifiy `functions/myFunction`. The entries are interpreted as regular expression, for example `functions/.*` matches all functions, `jobs/.*` matches all jobs, `classes/.*` matches all classes, `.*` matches all paths.
 * @property {Number} ttl The duration in seconds after which a request record is discarded from the database, defaults to 300s.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,7 +100,7 @@
 /**
  * @interface LiveQueryServerOptions
  * @property {String} appId This string should match the appId in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same appId.
- * @property {Number} cacheTimeout Number in milliseconds. When clients provide the sessionToken to the LiveQuery server, the LiveQuery server will try to fetch its ParseUser's objectId from parse server and store it in the cache. The value defines the duration of the cache. Check the following Security section and our protocol specification for details, defaults to 30 * 24 * 60 * 60 * 1000 ms (~30 days).
+ * @property {Number} cacheTimeout Number in milliseconds. When clients provide the sessionToken to the LiveQuery server, the LiveQuery server will try to fetch its ParseUser's objectId from parse server and store it in the cache. The value defines the duration of the cache. Check the following Security section and our protocol specification for details, defaults to 5 * 1000 ms (5 seconds).
  * @property {Any} keyPairs A JSON object that serves as a whitelist of keys. It is used for validating clients when they try to connect to the LiveQuery server. Check the following Security section and our protocol specification for details.
  * @property {String} logLevel This string defines the log level of the LiveQuery server. We support VERBOSE, INFO, ERROR, NONE, defaults to INFO.
  * @property {String} masterKey This string should match the masterKey in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same masterKey.
```
