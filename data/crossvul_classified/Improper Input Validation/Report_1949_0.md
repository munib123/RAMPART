# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1949_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1949_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 42-74 of the vulnerable file.

      case 'http2-settings':
      case 'te':
      case 'transfer-encoding':
      case 'proxy-connection':
      case 'keep-alive':
      case 'host':
        break
      default:
        dest[header] = headers[header]
        break
    }
  }
  return dest
}

// issue ref: https://github.com/fastify/fast-proxy/issues/42
function buildURL (source, reqBase) {
  const dest = new URL(source, reqBase)

  // if base is specified, source url should not override it
  if (reqBase && !reqBase.startsWith(dest.origin)) {
    throw new Error('source must be a relative path string')
  }

  return dest
}

module.exports = {
  copyHeaders,
  stripHttp1ConnectionHeaders,
  filterPseudoHeaders,
  buildURL
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,8 +59,14 @@
   const dest = new URL(source, reqBase)
 
   // if base is specified, source url should not override it
-  if (reqBase && !reqBase.startsWith(dest.origin)) {
-    throw new Error('source must be a relative path string')
+  if (reqBase) {
+    if (!reqBase.endsWith('/') && dest.href.length > reqBase.length) {
+      reqBase = reqBase + '/'
+    }
+
+    if (!dest.href.startsWith(reqBase)) {
+      throw new Error('source must be a relative path string')
+    }
   }
 
   return dest
```
