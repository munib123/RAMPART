# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 770_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `770_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 1051-1091 of the vulnerable file.

    return QuoteHelper.isIdentifierQuoted(identifier);
  }

  /**
   * Generates an SQL query that extract JSON property of given path.
   *
   * @param   {string}               column  The JSON column
   * @param   {string|Array<string>} [path]  The path to extract (optional)
   * @returns {string}                       The generated sql query
   * @private
   */
  jsonPathExtractionQuery(column, path) {
    let paths = _.toPath(path);
    let pathStr;
    const quotedColumn = this.isIdentifierQuoted(column)
      ? column
      : this.quoteIdentifier(column);

    switch (this.dialect) {
      case 'mysql':
        /**
         * Sub paths need to be quoted as ECMAScript identifiers
         * https://bugs.mysql.com/bug.php?id=81896
         */
        paths = paths.map(subPath => Utils.addTicks(subPath, '"'));
        pathStr = this.escape(['$'].concat(paths).join('.'));
        return `(${quotedColumn}->>${pathStr})`;

      case 'mariadb':
        pathStr = this.escape(['$'].concat(paths).join('.'));
        return `json_unquote(json_extract(${quotedColumn},${pathStr}))`;

      case 'sqlite':
        pathStr = this.escape(['$']
          .concat(paths)
          .join('.')
          .replace(/\.(\d+)(?:(?=\.)|$)/g, (_, digit) => `[${digit}]`));
        return `json_extract(${quotedColumn}, ${pathStr})`;

      case 'postgres':
        pathStr = this.escape(`{${paths.join(',')}}`);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1068,24 +1068,30 @@
 
     switch (this.dialect) {
       case 'mysql':
+      case 'mariadb':
+      case 'sqlite':
         /**
-         * Sub paths need to be quoted as ECMAScript identifiers
+         * Non digit sub paths need to be quoted as ECMAScript identifiers
          * https://bugs.mysql.com/bug.php?id=81896
          */
-        paths = paths.map(subPath => Utils.addTicks(subPath, '"'));
-        pathStr = this.escape(['$'].concat(paths).join('.'));
-        return `(${quotedColumn}->>${pathStr})`;
-
-      case 'mariadb':
-        pathStr = this.escape(['$'].concat(paths).join('.'));
-        return `json_unquote(json_extract(${quotedColumn},${pathStr}))`;
-
-      case 'sqlite':
+        if (this.dialect === 'mysql') {
+          paths = paths.map(subPath => {
+            return /\D/.test(subPath)
+              ? Utils.addTicks(subPath, '"')
+              : subPath;
+          });
+        }
+
         pathStr = this.escape(['$']
           .concat(paths)
           .join('.')
-          .replace(/\.(\d+)(?:(?=\.)|$)/g, (_, digit) => `[${digit}]`));
-        return `json_extract(${quotedColumn}, ${pathStr})`;
+          .replace(/\.(\d+)(?:(?=\.)|$)/g, (__, digit) => `[${digit}]`));
+
+        if (this.dialect === 'sqlite') {
+          return `json_extract(${quotedColumn},${pathStr})`;
+        }
+
+        return `json_unquote(json_extract(${quotedColumn},${pathStr}))`;
 
       case 'postgres':
         pathStr = this.escape(`{${paths.join(',')}}`);
```
