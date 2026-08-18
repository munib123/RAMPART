# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 1279_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1279_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 631-655 of the vulnerable file.

            return setTimeout(callback, 10, {result: false, message: err.message || 'Coin "'+coin+'" not found'});

        try { rows[0].info = JSON.parse(exports.Decrypt(rows[0].info));}
        catch(e) {callback({result: false, message: e.message});}

        if (rows[0].info.active != true)
            return setTimeout(callback, 10, {result: false, message: 'Coin "'+coin+'" is not active', info: rows[0].info});
 
        if (rows[0].info.orders == 'Disabled')
            return setTimeout(callback, 10, {result: false, message: 'Coin "'+coin+'" orders is temporarily disabled', info: rows[0].info});
        
        if (g_constants.share.tradeEnabled == false)
            return setTimeout(callback, 10, {result: false, message: 'Trading is temporarily disabled', info: rows[0].info});

        setTimeout(callback, 10, {result: true, info: rows[0].info});
    });
}

exports.GetCoinFromTicker = function(ticker, callback)
{
    g_constants.dbTables['coins'].selectAll('ROWID AS id, *', 'ticker="'+escape(ticker)+'"', '', (err, rows) => {
        if (err || !rows || !rows.length) return callback({});
        callback(rows[0]);
    })
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -648,8 +648,14 @@
 
 exports.GetCoinFromTicker = function(ticker, callback)
 {
-    g_constants.dbTables['coins'].selectAll('ROWID AS id, *', 'ticker="'+escape(ticker)+'"', '', (err, rows) => {
-        if (err || !rows || !rows.length) return callback({});
-        callback(rows[0]);
-    })
-}
+    return new Promise(async (ok, cancel) => {
+        try {
+            const rows = await g_constants.dbTables['coins'].Select('ROWID AS id, *', 'ticker="'+escape(ticker)+'"', '');
+            if (!rows || !rows.length || !rows[0].name) throw new Error('Coin ticker ('+escape(ticker)+') not found!');
+            return ok(rows[0]);
+        }
+        catch(e) {
+            return cancel(e);
+        }
+    });
+}
```
