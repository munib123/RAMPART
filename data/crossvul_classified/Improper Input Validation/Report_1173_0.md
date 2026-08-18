# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1173_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1173_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 8-48 of the vulnerable file.

const Types = require('./schema/index');
const castTextSearch = require('./schema/operators/text');
const get = require('./helpers/get');
const util = require('util');
const utils = require('./utils');

const ALLOWED_GEOWITHIN_GEOJSON_TYPES = ['Polygon', 'MultiPolygon'];

/**
 * Handles internal casting for query filters.
 *
 * @param {Schema} schema
 * @param {Object} obj Object to cast
 * @param {Object} options the query options
 * @param {Query} context passed to setters
 * @api private
 */
module.exports = function cast(schema, obj, options, context) {
  if (Array.isArray(obj)) {
    throw new Error('Query filter must be an object, got an array ', util.inspect(obj));
  }

  const paths = Object.keys(obj);
  let i = paths.length;
  let _keys;
  let any$conditionals;
  let schematype;
  let nested;
  let path;
  let type;
  let val;

  options = options || {};

  while (i--) {
    path = paths[i];
    val = obj[path];

    if (path === '$or' || path === '$nor' || path === '$and') {
      let k = val.length;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,6 +25,12 @@
 module.exports = function cast(schema, obj, options, context) {
   if (Array.isArray(obj)) {
     throw new Error('Query filter must be an object, got an array ', util.inspect(obj));
+  }
+
+  // bson 1.x has the unfortunate tendency to remove filters that have a top-level
+  // `_bsontype` property. Should remove this when we upgrade to bson 4.x. See gh-8222
+  if (obj.hasOwnProperty('_bsontype')) {
+    delete obj._bsontype;
   }
 
   const paths = Object.keys(obj);
```
