# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 4878_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4878_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 405-446 of the vulnerable file.


    return Utils._.template(query)({tableName: tableName, schemaJoin: schemaJoin, schemaWhere: schemaWhere});
  },

  removeIndexQuery: function(tableName, indexNameOrAttributes) {
    var sql = 'DROP INDEX IF EXISTS <%= indexName %>'
      , indexName = indexNameOrAttributes;

    if (typeof indexName !== 'string') {
      indexName = Utils.inflection.underscore(tableName + '_' + indexNameOrAttributes.join('_'));
    }

    return Utils._.template(sql)({
      tableName: this.quoteIdentifiers(tableName),
      indexName: this.quoteIdentifiers(indexName)
    });
  },

  addLimitAndOffset: function(options) {
    var fragment = '';
    if (options.limit) fragment += ' LIMIT ' + options.limit;
    if (options.offset) fragment += ' OFFSET ' + options.offset;

    return fragment;
  },

  attributeToSQL: function(attribute) {
    if (!Utils._.isPlainObject(attribute)) {
      attribute = {
        type: attribute
      };
    }

    var template = '<%= type %>'
      , replacements = {};

    if (attribute.type instanceof DataTypes.ENUM) {
      if (attribute.type.values && !attribute.values) attribute.values = attribute.type.values;

      if (Array.isArray(attribute.values) && (attribute.values.length > 0)) {
        replacements.type = 'ENUM(' + Utils._.map(attribute.values, function(value) {
          return this.escape(value);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -422,8 +422,8 @@
 
   addLimitAndOffset: function(options) {
     var fragment = '';
-    if (options.limit) fragment += ' LIMIT ' + options.limit;
-    if (options.offset) fragment += ' OFFSET ' + options.offset;
+    if (options.limit) fragment += ' LIMIT ' + this.escape(options.limit);
+    if (options.offset) fragment += ' OFFSET ' + this.escape(options.offset);
 
     return fragment;
   },
```
