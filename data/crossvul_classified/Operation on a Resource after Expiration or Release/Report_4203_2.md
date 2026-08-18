# CrossVul Fix Pair: Operation on a Resource after Expiration or Release in javascript
**Pair ID:** 4203_2
**Vulnerability Class:** Operation on a Resource after Expiration or Release
**CWE:** CWE-672
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4203_2`)

## Vulnerability Information & PoC

## Description
Operation on a Resource after Expiration or Release - The product uses, accesses, or otherwise operates on a resource after that resource has been expired, released, or revoked.

## Vulnerable Code
```javascript
Lines 461-501 of the vulnerable file.

  },
  redisURL: {
    env: 'PARSE_SERVER_LIVEQUERY_REDIS_URL',
    help: "parse-server's LiveQuery redisURL",
  },
  wssAdapter: {
    env: 'PARSE_SERVER_LIVEQUERY_WSS_ADAPTER',
    help: 'Adapter module for the WebSocketServer',
    action: parsers.moduleOrObjectParser,
  },
};
module.exports.LiveQueryServerOptions = {
  appId: {
    env: 'PARSE_LIVE_QUERY_SERVER_APP_ID',
    help:
      'This string should match the appId in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same appId.',
  },
  cacheTimeout: {
    env: 'PARSE_LIVE_QUERY_SERVER_CACHE_TIMEOUT',
    help:
      "Number in milliseconds. When clients provide the sessionToken to the LiveQuery server, the LiveQuery server will try to fetch its ParseUser's objectId from parse server and store it in the cache. The value defines the duration of the cache. Check the following Security section and our protocol specification for details, defaults to 30 * 24 * 60 * 60 * 1000 ms (~30 days).",
    action: parsers.numberParser('cacheTimeout'),
  },
  keyPairs: {
    env: 'PARSE_LIVE_QUERY_SERVER_KEY_PAIRS',
    help:
      'A JSON object that serves as a whitelist of keys. It is used for validating clients when they try to connect to the LiveQuery server. Check the following Security section and our protocol specification for details.',
    action: parsers.objectParser,
  },
  logLevel: {
    env: 'PARSE_LIVE_QUERY_SERVER_LOG_LEVEL',
    help:
      'This string defines the log level of the LiveQuery server. We support VERBOSE, INFO, ERROR, NONE, defaults to INFO.',
  },
  masterKey: {
    env: 'PARSE_LIVE_QUERY_SERVER_MASTER_KEY',
    help:
      'This string should match the masterKey in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same masterKey.',
  },
  port: {
    env: 'PARSE_LIVE_QUERY_SERVER_PORT',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -478,7 +478,7 @@
   cacheTimeout: {
     env: 'PARSE_LIVE_QUERY_SERVER_CACHE_TIMEOUT',
     help:
-      "Number in milliseconds. When clients provide the sessionToken to the LiveQuery server, the LiveQuery server will try to fetch its ParseUser's objectId from parse server and store it in the cache. The value defines the duration of the cache. Check the following Security section and our protocol specification for details, defaults to 30 * 24 * 60 * 60 * 1000 ms (~30 days).",
+      "Number in milliseconds. When clients provide the sessionToken to the LiveQuery server, the LiveQuery server will try to fetch its ParseUser's objectId from parse server and store it in the cache. The value defines the duration of the cache. Check the following Security section and our protocol specification for details, defaults to 5 * 1000 ms (5 seconds).",
     action: parsers.numberParser('cacheTimeout'),
   },
   keyPairs: {
```
