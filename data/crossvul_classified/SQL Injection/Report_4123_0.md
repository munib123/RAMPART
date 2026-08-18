# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4123_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4123_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 378-420 of the vulnerable file.

            || (false === Validate::isString($location))
        ) {
            $serializedInputData = [
                'id_product' => $id_product,
                'id_shop' => $id_shop,
                'id_product_attribute' => $id_product_attribute,
                'location' => $location,
            ];

            throw new \InvalidArgumentException(sprintf(
                'Could not update location as input data is not valid: %s',
                json_encode($serializedInputData)
            ));
        }

        $existing_id = StockAvailable::getStockAvailableIdByProductId($id_product, $id_product_attribute, $id_shop);

        if ($existing_id > 0) {
            Db::getInstance()->update(
                'stock_available',
                array('location' => $location),
                'id_product = ' . $id_product .
                (($id_product_attribute) ? ' AND id_product_attribute = ' . $id_product_attribute : '') .
                StockAvailable::addSqlShopRestriction(null, $id_shop)
            );
        } else {
            $params = array(
                'location' => $location,
                'id_product' => $id_product,
                'id_product_attribute' => $id_product_attribute,
            );

            StockAvailable::addSqlShopParams($params, $id_shop);
            Db::getInstance()->insert('stock_available', $params, false, true, Db::ON_DUPLICATE_KEY);
        }
    }

    /**
     * For a given id_product and id_product_attribute, gets its stock available.
     *
     * @param int $id_product
     * @param int $id_product_attribute Optional
     * @param int $id_shop Optional : gets context by default
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -395,17 +395,17 @@
         if ($existing_id > 0) {
             Db::getInstance()->update(
                 'stock_available',
-                array('location' => $location),
-                'id_product = ' . $id_product .
-                (($id_product_attribute) ? ' AND id_product_attribute = ' . $id_product_attribute : '') .
+                ['location' => pSQL($location)],
+                'id_product = ' . (int) $id_product .
+                (($id_product_attribute) ? ' AND id_product_attribute = ' . (int) $id_product_attribute : '') .
                 StockAvailable::addSqlShopRestriction(null, $id_shop)
             );
         } else {
-            $params = array(
-                'location' => $location,
-                'id_product' => $id_product,
-                'id_product_attribute' => $id_product_attribute,
-            );
+            $params = [
+                'location' => pSQL($location),
+                'id_product' => (int) $id_product,
+                'id_product_attribute' => (int) $id_product_attribute,
+            ];
 
             StockAvailable::addSqlShopParams($params, $id_shop);
             Db::getInstance()->insert('stock_available', $params, false, true, Db::ON_DUPLICATE_KEY);
```
