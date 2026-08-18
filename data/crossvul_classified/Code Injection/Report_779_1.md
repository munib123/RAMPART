# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 779_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `779_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 1-41 of the vulnerable file.

/** @module bodymen */
import _ from 'lodash'
import Param from 'rich-param'
import Schema from './bodymen-schema'

export { Param, Schema }

export const handlers = {
  formatters: {},
  validators: {}
}

/**
 * Get or set a handler.
 * @memberof bodymen
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
 * Get or set a formatter.
 * @memberof bodymen
 * @param {string} name - Formatter name.
 * @param {formatterFn} [fn] - Set the formatter method.
 * @return {formatterFn} The formatter method.
 */
export function formatter (name, fn) {
  return handler('formatters', ...arguments)
}

/**
 * Get or set a validator.
 * @memberof bodymen
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,14 @@
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
