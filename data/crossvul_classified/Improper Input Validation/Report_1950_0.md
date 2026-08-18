# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1950_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1950_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 36-89 of the vulnerable file.

    closeWebSocket(source, code, reason)
    closeWebSocket(target, code, reason)
  }

  source.on('message', data => waitConnection(target, () => target.send(data)))
  source.on('ping', data => waitConnection(target, () => target.ping(data)))
  source.on('pong', data => waitConnection(target, () => target.pong(data)))
  source.on('close', close)
  source.on('error', error => close(1011, error.message))
  source.on('unexpected-response', () => close(1011, 'unexpected response'))

  // source WebSocket is already connected because it is created by ws server
  target.on('message', data => source.send(data))
  target.on('ping', data => source.ping(data))
  target.on('pong', data => source.pong(data))
  target.on('close', close)
  target.on('error', error => close(1011, error.message))
  target.on('unexpected-response', () => close(1011, 'unexpected response'))
}

function createWebSocketUrl (options, request) {
  const source = new URL(request.url, 'http://127.0.0.1')

  const target = new URL(
    options.rewritePrefix || options.prefix || source.pathname,
    options.upstream
  )

  target.search = source.search

  return target
}

function setupWebSocketProxy (fastify, options) {
  const server = new WebSocket.Server({
    path: options.prefix,
    server: fastify.server,
    ...options.wsServerOptions
  })

  fastify.addHook('onClose', (instance, done) => server.close(done))

  // To be able to close the HTTP server,
  // all WebSocket clients need to be disconnected.
  // Fastify is missing a pre-close event, or the ability to
  // add a hook before the server.close call. We need to resort
  // to monkeypatching for now.
  const oldClose = fastify.server.close
  fastify.server.close = function (done) {
    for (const client of server.clients) {
      client.close()
    }
    oldClose.call(this, done)
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,22 +53,8 @@
   target.on('unexpected-response', () => close(1011, 'unexpected response'))
 }
 
-function createWebSocketUrl (options, request) {
-  const source = new URL(request.url, 'http://127.0.0.1')
-
-  const target = new URL(
-    options.rewritePrefix || options.prefix || source.pathname,
-    options.upstream
-  )
-
-  target.search = source.search
-
-  return target
-}
-
-function setupWebSocketProxy (fastify, options) {
+function setupWebSocketProxy (fastify, options, rewritePrefix) {
   const server = new WebSocket.Server({
-    path: options.prefix,
     server: fastify.server,
     ...options.wsServerOptions
   })
@@ -93,13 +79,46 @@
   })
 
   server.on('connection', (source, request) => {
-    const url = createWebSocketUrl(options, request)
+    if (fastify.prefix && !request.url.startsWith(fastify.prefix)) {
+      fastify.log.debug({ url: request.url }, 'not matching prefix')
+      source.close()
+      return
+    }
+
+    const url = createWebSocketUrl(request)
 
     const target = new WebSocket(url, options.wsClientOptions)
 
     fastify.log.debug({ url: url.href }, 'proxy websocket')
     proxyWebSockets(source, target)
   })
+
+  function createWebSocketUrl (request) {
+    const source = new URL(request.url, 'http://127.0.0.1')
+
+    const target = new URL(
+      source.pathname.replace(fastify.prefix, rewritePrefix),
+      options.upstream
+    )
+
+    target.search = source.search
+
+    return target
+  }
+}
+
+function generateRewritePrefix (prefix, opts) {
+  if (!prefix) {
+    return ''
+  }
+
+  let rewritePrefix = opts.rewritePrefix || new URL(opts.upstream).pathname
+
+  if (!prefix.endsWith('/') && rewritePrefix.endsWith('/')) {
+    rewritePrefix = rewritePrefix.slice(0, -1)
+  }
+
+  return rewritePrefix
 }
 
 async function httpProxy (fastify, opts) {
@@ -108,7 +127,7 @@
   }
 
   const preHandler = opts.preHandler || opts.beforeHandler
-  const rewritePrefix = opts.rewritePrefix || ''
+  const rewritePrefix = generateRewritePrefix(fastify.prefix, opts)
 
   const fromOpts = Object.assign({}, opts)
   fromOpts.base = opts.upstream
@@ -164,7 +183,7 @@
   }
 
   if (opts.websocket) {
-    setupWebSocketProxy(fastify, opts)
+    setupWebSocketProxy(fastify, opts, rewritePrefix)
   }
 }
 
```
