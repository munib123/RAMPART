# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 769_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `769_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 2181-2221 of the vulnerable file.

    if (_.isPlainObject(value) && fieldType instanceof DataTypes.JSON && options.json !== false) {
      return (function () {
        var $items = []
          , result
          , traverse;

        traverse = function (prop, item, path) {
          var $where = {}
            , $key
            , $cast
            , $baseKey
            , $tmp
            , castKey;

          if (path[path.length - 1].indexOf('::') > -1) {
            $tmp = path[path.length - 1].split('::');
            $cast = $tmp[1];
            path[path.length - 1] = $tmp[0];
          }

          $baseKey = self.quoteIdentifier(key)+'#>>\'{'+path.join(', ')+'}\'';

          if (options.prefix) {
            if (options.prefix instanceof Utils.literal) {
              $baseKey = self.handleSequelizeMethod(options.prefix)+'.'+$baseKey;
            } else {
              $baseKey = self.quoteTable(options.prefix)+'.'+$baseKey;
            }
          }

          $baseKey = '('+$baseKey+')';

          castKey = function ($item) {
            var key = $baseKey;

            if (!$cast) {
              if (typeof $item === 'number') {
                $cast = 'double precision';
              } else if ($item instanceof Date) {
                $cast = 'timestamptz';
              } else if (typeof $item === 'boolean') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2198,7 +2198,8 @@
             path[path.length - 1] = $tmp[0];
           }
 
-          $baseKey = self.quoteIdentifier(key)+'#>>\'{'+path.join(', ')+'}\'';
+          var pathKey = self.escape('{' + path.join(', ') + '}');
+          $baseKey = self.quoteIdentifier(key)+'#>>'+pathKey;
 
           if (options.prefix) {
             if (options.prefix instanceof Utils.literal) {
```
