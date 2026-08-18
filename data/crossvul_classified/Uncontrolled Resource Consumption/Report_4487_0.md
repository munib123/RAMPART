# CrossVul Fix Pair: Uncontrolled Resource Consumption in javascript
**Pair ID:** 4487_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4487_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```javascript
Lines 9-49 of the vulnerable file.


class Server extends EventEmitter {
  /**
   * Server constructor.
   *
   * @param {Object} options
   * @api public
   */
  constructor(opts = {}) {
    super();

    this.clients = {};
    this.clientsCount = 0;

    this.opts = Object.assign(
      {
        wsEngine: process.env.EIO_WS_ENGINE || "ws",
        pingTimeout: 5000,
        pingInterval: 25000,
        upgradeTimeout: 10000,
        maxHttpBufferSize: 10e7,
        transports: Object.keys(transports),
        allowUpgrades: true,
        perMessageDeflate: {
          threshold: 1024
        },
        httpCompression: {
          threshold: 1024
        },
        cors: false
      },
      opts
    );

    if (opts.cookie) {
      this.opts.cookie = Object.assign(
        {
          name: "io",
          path: "/",
          httpOnly: opts.cookie.path !== false,
          sameSite: "lax"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
         pingTimeout: 5000,
         pingInterval: 25000,
         upgradeTimeout: 10000,
-        maxHttpBufferSize: 10e7,
+        maxHttpBufferSize: 1e6,
         transports: Object.keys(transports),
         allowUpgrades: true,
         perMessageDeflate: {
```
