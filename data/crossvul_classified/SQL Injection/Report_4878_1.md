# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 4878_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4878_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 1725-1765 of the vulnerable file.

   * @return {String}         The generated sql query.
   */
  rollbackTransactionQuery: function(transaction, options) {
    if (options.parent) {
      return 'ROLLBACK TO SAVEPOINT ' + this.quoteIdentifier(transaction.name) + ';';
    }

    return 'ROLLBACK;';
  },

  /**
   * Returns an SQL fragment for adding result constraints
   *
   * @param  {Object} options An object with selectQuery options.
   * @param  {Object} options The model passed to the selectQuery.
   * @return {String}         The generated sql query.
   */
  addLimitAndOffset: function(options, model) {
    var fragment = '';
    if (options.offset && !options.limit) {
      fragment += ' LIMIT ' + options.offset + ', ' + 18440000000000000000;
    } else if (options.limit) {
      if (options.offset) {
        fragment += ' LIMIT ' + options.offset + ', ' + options.limit;
      } else {
        fragment += ' LIMIT ' + options.limit;
      }
    }

    return fragment;
  },

  handleSequelizeMethod: function (smth, tableName, factory, options, prepend) {
    var self = this
      , result;

    if (smth instanceof Utils.where) {
      var value = smth.logic
        , key;

      if (smth.attribute._isSequelizeMethod) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1742,12 +1742,12 @@
   addLimitAndOffset: function(options, model) {
     var fragment = '';
     if (options.offset && !options.limit) {
-      fragment += ' LIMIT ' + options.offset + ', ' + 18440000000000000000;
+      fragment += ' LIMIT ' + this.escape(options.offset) + ', ' + 18440000000000000000;
     } else if (options.limit) {
       if (options.offset) {
-        fragment += ' LIMIT ' + options.offset + ', ' + options.limit;
+        fragment += ' LIMIT ' + this.escape(options.offset) + ', ' + this.escape(options.limit);
       } else {
-        fragment += ' LIMIT ' + options.limit;
+        fragment += ' LIMIT ' + this.escape(options.limit);
       }
     }
 
```
