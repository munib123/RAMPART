# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 1279_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1279_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 151-191 of the vulnerable file.

                    
                retData.buy.push({Quantity: ret.data.buy[i].amount, Rate: ret.data.buy[i].price});
            }
        }
        if (type == 'both' || type == 'sell')
        {
            for (var i=0; i<ret.data.sell.length; i++)
            {
                if (ret > 200)
                    break;
                if (!ret.data.sell[i].amount || !ret.data.sell[i].price)    
                    continue;
                    
                retData.sell.push({Quantity: ret.data.sell[i].amount, Rate: ret.data.sell[i].price});
            }
        }
        onSuccess(req, res, retData);
    });
}

exports.onGetMarketSummary = function(req, res)
{
    const dataParsed = url.parse(req.url);
    if (!dataParsed || !dataParsed.query)
        return onError(req, res, 'Bad request');

    const queryStr = querystring.parse(dataParsed.query);
    if (!queryStr.market)
        return onError(req, res, 'Bad request. Parameter "market" not found');
        
    const period = (queryStr.period && (queryStr.period == 24 || queryStr.period == 250 || queryStr.period == 1000 || queryStr.period == 6000)) ? queryStr.period*1 : 24;

    console.log('period='+period+" queryStr="+JSON.stringify(queryStr));
    if (!utils.isNumeric(period))
        return onError(req, res, 'Bad request. Period is not numeric');
    
    const data = queryStr.market.split('-');
    if (!data || !data.length || data.length != 2)
        return onError(req, res, 'Bad request. Parameter "market" is invalid');

    const MarketName = queryStr.market;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,7 +168,7 @@
     });
 }
 
-exports.onGetMarketSummary = function(req, res)
+exports.onGetMarketSummary = async function(req, res)
 {
     const dataParsed = url.parse(req.url);
     if (!dataParsed || !dataParsed.query)
@@ -190,16 +190,19 @@
 
     const MarketName = queryStr.market;
     
-    g_constants.dbTables['coins'].selectAll('name, ticker, info, icon', 'ticker="'+data[1]+'"', '', (err, rows) => {
-        if (err || !rows)
-            return onError(req, res, err && err.message ? err.message : 'unknown database error');
-
-        if (!rows.length)
-            return onError(req, res, 'ticker '+data[1]+' not found');
-
-        const COIN = rows[0];
-        const coin_icon_src = rows[0].icon;
-        const coin_info = JSON.parse(utils.Decrypt(rows[0].info));
+    try
+    {
+    //g_constants.dbTables['coins'].selectAll('name, ticker, info, icon', 'ticker="'+data[1]+'"', '', (err, rows) => {
+    //    if (err || !rows)
+    //        return onError(req, res, err && err.message ? err.message : 'unknown database error');
+
+        //if (!rows.length)
+        //    return onError(req, res, 'ticker '+data[1]+' not found');
+
+        //const COIN = rows[0];
+        const COIN = await utils.GetCoinFromTicker(data[1]);
+        const coin_icon_src = COIN.icon;
+        const coin_info = JSON.parse(utils.Decrypt(COIN.info));
         
         const WHERE = 'coin="'+COIN.name+'" AND time*1 > ('+Date.now()+'*1 - '+period+'*3600*1000)';
         
@@ -207,11 +210,8 @@
         
         let ret = GetCache(METHOD);
         if (ret)
-        {
-            onSuccess(req, res, ret);
-            return;
-        }
-        
+            return onSuccess(req, res, ret);
+
         g_constants.dbTables['history'].selectAll('max((fromBuyerToSeller*1)/fromSellerToBuyer) AS Height, min((fromBuyerToSeller*1)/fromSellerToBuyer) AS Low, sum(fromSellerToBuyer*1) AS Volume', WHERE, 'GROUP BY coin', (err, rows) => {
             if (err || !rows)
             {
@@ -254,7 +254,12 @@
             
          });
         
-    });
+    }
+    catch (e)
+    {
+        return onError(req, res, e.message || 'unknown error');
+    }
+    //});
 }
 
 exports.onGetMarketHistory = function(req, res)
@@ -310,7 +315,7 @@
     });
 }
 
-function SubmitOrder(req, res, buysell)
+async function SubmitOrder(req, res, buysell)
 {
     try
     {
@@ -323,7 +328,7 @@
         const currency = queryStr.market.split('-');
         if (!currency.length || currency.length != 2) throw new Error('Bad request. Parameter currency is invalid.');
         
-        utils.GetCoinFromTicker(currency[1], coin => {
+        const coin = await utils.GetCoinFromTicker(currency[1]); //, coin => {
             if (!coin || !coin.name) 
                 return onError(req, res, 'Coin ticker not found');
 
@@ -352,7 +357,7 @@
                     return onError(req, res, e.message);
                 }
             })
-        });    
+        //});    
     }
     catch(e) {
         return onError(req, res, e.message);
@@ -417,7 +422,7 @@
     }
 }
 
-exports.onMarketGetOpenOrders = function(req, res)
+exports.onMarketGetOpenOrders = async function(req, res)
 {
     try
     {
@@ -430,7 +435,7 @@
         const currency = queryStr.market.split('-');
         if (!currency.length || currency.length != 2) throw new Error('Bad request. Parameter currency is invalid.');
         
-        utils.GetCoinFromTicker(currency[1], coin => {
+        const coin = await utils.GetCoinFromTicker(currency[1]); //, coin => {
             if (!coin || !coin.name) 
                 return onError(req, res, 'Coin ticker not found');
 
@@ -468,14 +473,14 @@
                     return onError(req, res, e.message);
                 }
             })
-        });    
+        //});    
     }
     catch(e) {
         return onError(req, res, e.message);
     }
 }
 
-exports.onAccountGetBalance = function(req, res)
+exports.onAccountGetBalance = async function(req, res)
 {
     try
     {
@@ -485,7 +490,7 @@
         const queryStr = querystring.parse(dataParsed.query);
         if (!queryStr.apikey || !queryStr.nonce || !queryStr.currency) throw new Error('Bad request. Required parameter (apikey or nonce or currency) not found.');
     
-        utils.GetCoinFromTicker(queryStr.currency, coin => {
+        const coin = await utils.GetCoinFromTicker(queryStr.currency);//, coin => {
             if (!coin || !coin.name) 
                 return onError(req, res, 'Coin ticker not found');
 
@@ -516,7 +521,7 @@
                     return onError(req, res, e.message);
                 }
             })
-        });    
+        //});    
     }
     catch(e) {
         return onError(req, res, e.message);
@@ -599,7 +604,7 @@
     }
 }
 
-exports.onAccountGetDepositAddress = function(req, res)
+exports.onAccountGetDepositAddress = async function(req, res)
 {
     const dataParsed = url.parse(req.url);
     if (!dataParsed || !dataParsed.query || !req.headers['apisign'])
@@ -609,7 +614,7 @@
     if (!queryStr.apikey || !queryStr.nonce || !queryStr.currency)
         return onError(req, res, 'Bad request. Required parameter (apikey or nonce or currency) not found.');
     
-    utils.GetCoinFromTicker(queryStr.currency, coin => {
+    const coin = utils.GetCoinFromTicker(queryStr.currency); //, coin => {
         if (!coin || !coin.name) 
             return onError(req, res, 'Coin ticker not found');
 
@@ -632,7 +637,7 @@
                 return onError(req, res, e.message);
             }
         })
-    });    
+    //});    
 }
 
 exports.onAccountGetOrder = function(req, res)
@@ -745,7 +750,7 @@
 }
 
 
-exports.onAccountWithdraw = function(req, res)
+exports.onAccountWithdraw = async function(req, res)
 {
     const dataParsed = url.parse(req.url);
     if (!dataParsed || !dataParsed.query || !req.headers['apisign'])
@@ -761,7 +766,7 @@
     if (queryStr.quantity < 0.00001)
         return onError(req, res, 'Bad request. quantity < 0.00001 (is too low)');
 
-    utils.GetCoinFromTicker(queryStr.currency, coin => {
+    const coin = await utils.GetCoinFromTicker(queryStr.currency); //, coin => {
         if (!coin || !coin.name) 
             return onError(req, res, 'Coin ticker not found');
 
@@ -814,7 +819,7 @@
                 });
             }
         }, req);
-    });
+    //});
 }
 
 function CheckAPIkey(strKey, strSign, strQuery, callback, req)
```
