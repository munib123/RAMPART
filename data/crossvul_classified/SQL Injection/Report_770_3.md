# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 770_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `770_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

'use strict';

const Utils = require('../../utils');
const util = require('util');
const Transaction = require('../../transaction');
const _ = require('lodash');
const MySqlQueryGenerator = require('../mysql/query-generator');
const AbstractQueryGenerator = require('../abstract/query-generator');

class SQLiteQueryGenerator extends MySqlQueryGenerator {
  createSchema() {
    return "SELECT name FROM `sqlite_master` WHERE type='table' and name!='sqlite_sequence';";
  }

  showSchemasQuery() {
    return "SELECT name FROM `sqlite_master` WHERE type='table' and name!='sqlite_sequence';";
  }

  versionQuery() {
    return 'SELECT sqlite_version() as `version`';
  }

  createTableQuery(tableName, attributes, options) {
    options = options || {};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,6 @@
 'use strict';
 
 const Utils = require('../../utils');
-const util = require('util');
 const Transaction = require('../../transaction');
 const _ = require('lodash');
 const MySqlQueryGenerator = require('../mysql/query-generator');
@@ -149,34 +148,10 @@
 
   handleSequelizeMethod(smth, tableName, factory, options, prepend) {
     if (smth instanceof Utils.Json) {
-      // Parse nested object
-      if (smth.conditions) {
-        const conditions = this.parseConditionObject(smth.conditions).map(condition =>
-          `${this.jsonPathExtractionQuery(condition.path[0], _.tail(condition.path))} = '${condition.value}'`
-        );
-
-        return conditions.join(' AND ');
-      }
-      if (smth.path) {
-        let str;
-
-        // Allow specifying conditions using the sqlite json functions
-        if (this._checkValidJsonStatement(smth.path)) {
-          str = smth.path;
-        } else {
-          // Also support json property accessors
-          const paths = _.toPath(smth.path);
-          const column = paths.shift();
-          str = this.jsonPathExtractionQuery(column, paths);
-        }
-
-        if (smth.value) {
-          str += util.format(' = %s', this.escape(smth.value));
-        }
-
-        return str;
-      }
-    } else if (smth instanceof Utils.Cast) {
+      return super.handleSequelizeMethod(smth, tableName, factory, options, prepend);
+    }
+
+    if (smth instanceof Utils.Cast) {
       if (/timestamp/i.test(smth.type)) {
         smth.type = 'datetime';
       }
```
