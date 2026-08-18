# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4607_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4607_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 2-42 of the vulnerable file.

import _ from 'lodash'
import Param from './querymen-param'
import Schema from './querymen-schema'

export { Param, Schema }

export let handlers = {
  parsers: {},
  formatters: {},
  validators: {}
}

/**
 * Get or set a handler.
 * @memberof querymen
 * @param {string} type - Handler type.
 * @param {string} name - Handler name.
 * @param {Function} [fn] - Set the handler method.
 */
export function handler (type, name, fn) {
  if (arguments.length > 2) {
    handlers[type][name] = fn
  }

  return handlers[type][name]
}

/**
 * Get or set a parser.
 * @memberof querymen
 * @param {string} name - Parser name.
 * @param {parserFn} [fn] - Set the parser method.
 * @return {parserFn} The parser method.
 */
export function parser (name, fn) {
  return handler('parsers', ...arguments)
}

/**
 * Get or set a formatter.
 * @memberof querymen
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,14 @@
  * @param {Function} [fn] - Set the handler method.
  */
 export function handler (type, name, fn) {
+  if (
+    type === 'constructor' ||
+    type === '__proto__' ||
+    name === 'constructor' ||
+    name === '__proto__'
+  ) {
+    return
+  }
   if (arguments.length > 2) {
     handlers[type][name] = fn
   }
```
