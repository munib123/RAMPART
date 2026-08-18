# CrossVul Fix Pair: Operation on a Resource after Expiration or Release in javascript
**Pair ID:** 4203_5
**Vulnerability Class:** Operation on a Resource after Expiration or Release
**CWE:** CWE-672
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4203_5`)

## Vulnerability Information & PoC

## Description
Operation on a Resource after Expiration or Release - The product uses, accesses, or otherwise operates on a resource after that resource has been expired, released, or revoked.

## Vulnerable Code
```javascript
Lines 281-321 of the vulnerable file.

        graphQLPath: options.graphQLPath,
        playgroundPath: options.playgroundPath,
        graphQLCustomTypeDefs,
      });

      if (options.mountGraphQL) {
        parseGraphQLServer.applyGraphQL(app);
      }

      if (options.mountPlayground) {
        parseGraphQLServer.applyPlayground(app);
      }
    }

    const server = app.listen(options.port, options.host, callback);
    this.server = server;

    if (options.startLiveQueryServer || options.liveQueryServerOptions) {
      this.liveQueryServer = ParseServer.createLiveQueryServer(
        server,
        options.liveQueryServerOptions
      );
    }
    /* istanbul ignore next */
    if (!process.env.TESTING) {
      configureListeners(this);
    }
    this.expressApp = app;
    return this;
  }

  /**
   * Creates a new ParseServer and starts it.
   * @param {ParseServerOptions} options used to start the server
   * @param {Function} callback called when the server has started
   * @returns {ParseServer} the parse server instance
   */
  static start(options: ParseServerOptions, callback: ?() => void) {
    const parseServer = new ParseServer(options);
    return parseServer.start(options, callback);
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -298,7 +298,8 @@
     if (options.startLiveQueryServer || options.liveQueryServerOptions) {
       this.liveQueryServer = ParseServer.createLiveQueryServer(
         server,
-        options.liveQueryServerOptions
+        options.liveQueryServerOptions,
+        options
       );
     }
     /* istanbul ignore next */
@@ -324,16 +325,21 @@
    * Helper method to create a liveQuery server
    * @static
    * @param {Server} httpServer an optional http server to pass
-   * @param {LiveQueryServerOptions} config options fot he liveQueryServer
+   * @param {LiveQueryServerOptions} config options for the liveQueryServer
+   * @param {ParseServerOptions} options options for the ParseServer
    * @returns {ParseLiveQueryServer} the live query server instance
    */
-  static createLiveQueryServer(httpServer, config: LiveQueryServerOptions) {
+  static createLiveQueryServer(
+    httpServer,
+    config: LiveQueryServerOptions,
+    options: ParseServerOptions
+  ) {
     if (!httpServer || (config && config.port)) {
       var app = express();
       httpServer = require('http').createServer(app);
       httpServer.listen(config.port);
     }
-    return new ParseLiveQueryServer(httpServer, config);
+    return new ParseLiveQueryServer(httpServer, config, options);
   }
 
   static verifyServerUrl(callback) {
```
