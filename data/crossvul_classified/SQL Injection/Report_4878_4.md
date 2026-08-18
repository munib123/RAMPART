# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 4878_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4878_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 70-124 of the vulnerable file.

    , pkString = primaryKeys.map(function(pk) { return this.quoteIdentifier(pk); }.bind(this)).join(', ');

    if (!!options.uniqueKeys) {
      Utils._.each(options.uniqueKeys, function(columns) {
        if (!columns.singleField) { // If it's a single field its handled in column def, not as an index
          values.attributes += ', UNIQUE (' + columns.fields.join(', ') + ')';
        }
      });
    }

    if (pkString.length > 0) {
      values.attributes += ', PRIMARY KEY (' + pkString + ')';
    }

    var sql = Utils._.template(query)(values).trim() + ';';
    return this.replaceBooleanDefaults(sql);
  },

  booleanValue: function(value){
    return !!value ? 1 : 0;
  },

  addLimitAndOffset: function(options){
    var fragment = '';
    if (options.offset && !options.limit) {
      fragment += ' LIMIT ' + options.offset + ', ' + 10000000000000;
    } else if (options.limit) {
      if (options.offset) {
        fragment += ' LIMIT ' + options.offset + ', ' + options.limit;
      } else {
        fragment += ' LIMIT ' + options.limit;
      }
    }

    return fragment;
  },

  addColumnQuery: function(table, key, dataType) {
    var query = 'ALTER TABLE <%= table %> ADD <%= attribute %>;'
      , attributes = {};

    attributes[key] = dataType;
    var fields = this.attributesToSQL(attributes, {
      context: 'addColumn'
    });
    var attribute = Utils._.template('<%= key %> <%= definition %>')({
        key: this.quoteIdentifier(key),
        definition: fields[key]
      });

    var sql =  Utils._.template(query)({
      table: this.quoteTable(table),
      attribute: attribute
    });

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,21 +87,6 @@
 
   booleanValue: function(value){
     return !!value ? 1 : 0;
-  },
-
-  addLimitAndOffset: function(options){
-    var fragment = '';
-    if (options.offset && !options.limit) {
-      fragment += ' LIMIT ' + options.offset + ', ' + 10000000000000;
-    } else if (options.limit) {
-      if (options.offset) {
-        fragment += ' LIMIT ' + options.offset + ', ' + options.limit;
-      } else {
-        fragment += ' LIMIT ' + options.limit;
-      }
-    }
-
-    return fragment;
   },
 
   addColumnQuery: function(table, key, dataType) {
```
