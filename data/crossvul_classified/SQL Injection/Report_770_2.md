# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 770_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `770_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 192-232 of the vulnerable file.


    return `ALTER TABLE ${this.quoteTable(tableName)} ${finalQuery};`;
  }

  renameColumnQuery(tableName, attrBefore, attributes) {
    const attrString = [];

    for (const attrName in attributes) {
      const definition = attributes[attrName];
      attrString.push(`\`${attrBefore}\` \`${attrName}\` ${definition}`);
    }

    return `ALTER TABLE ${this.quoteTable(tableName)} CHANGE ${attrString.join(', ')};`;
  }

  handleSequelizeMethod(smth, tableName, factory, options, prepend) {
    if (smth instanceof Utils.Json) {
      // Parse nested object
      if (smth.conditions) {
        const conditions = this.parseConditionObject(smth.conditions).map(condition =>
          `${this.quoteIdentifier(condition.path[0])}->>'$.${_.tail(condition.path).join('.')}' = '${condition.value}'`
        );

        return conditions.join(' and ');
      }
      if (smth.path) {
        let str;

        // Allow specifying conditions using the sqlite json functions
        if (this._checkValidJsonStatement(smth.path)) {
          str = smth.path;
        } else {
          // Also support json dot notation
          let path = smth.path;
          let startWithDot = true;

          // Convert .number. to [number].
          path = path.replace(/\.(\d+)\./g, '[$1].');
          // Convert .number$ to [number]
          path = path.replace(/\.(\d+)$/, '[$1]');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -209,10 +209,10 @@
       // Parse nested object
       if (smth.conditions) {
         const conditions = this.parseConditionObject(smth.conditions).map(condition =>
-          `${this.quoteIdentifier(condition.path[0])}->>'$.${_.tail(condition.path).join('.')}' = '${condition.value}'`
+          `${this.jsonPathExtractionQuery(condition.path[0], _.tail(condition.path))} = '${condition.value}'`
         );
 
-        return conditions.join(' and ');
+        return conditions.join(' AND ');
       }
       if (smth.path) {
         let str;
@@ -221,27 +221,10 @@
         if (this._checkValidJsonStatement(smth.path)) {
           str = smth.path;
         } else {
-          // Also support json dot notation
-          let path = smth.path;
-          let startWithDot = true;
-
-          // Convert .number. to [number].
-          path = path.replace(/\.(\d+)\./g, '[$1].');
-          // Convert .number$ to [number]
-          path = path.replace(/\.(\d+)$/, '[$1]');
-
-          path = path.split('.');
-
-          let columnName = path.shift();
-          const match = columnName.match(/\[\d+\]$/);
-          // If columnName ends with [\d+]
-          if (match !== null) {
-            path.unshift(columnName.substr(match.index));
-            columnName = columnName.substr(0, match.index);
-            startWithDot = false;
-          }
-
-          str = `${this.quoteIdentifier(columnName)}->>'$${startWithDot ? '.' : ''}${path.join('.')}'`;
+          // Also support json property accessors
+          const paths = _.toPath(smth.path);
+          const column = paths.shift();
+          str = this.jsonPathExtractionQuery(column, paths);
         }
 
         if (smth.value) {
```
