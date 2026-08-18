# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5160_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5160_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 886-926 of the vulnerable file.

                    break;
                case 'CREATE DATABASE':
                    self::createDatabaseVersion($dbname, '1', $query);
                    break;
                } // end switch
            }

            // If version exists
            if (self::isTracked($dbname, $result['tablename']) && $version != -1) {
                if ($result['type'] == 'DDL') {
                    $save_to = 'schema_sql';
                } elseif ($result['type'] == 'DML') {
                    $save_to = 'data_sql';
                } else {
                    $save_to = '';
                }
                $date  = date('Y-m-d H:i:s');

                // Cut off `dbname`. from query
                $query = preg_replace(
                    '/`' . preg_quote($dbname) . '`\s?\./',
                    '',
                    $query
                );

                // Add log information
                $query = self::getLogComment() . $query ;

                // Mark it as untouchable
                $sql_query = " /*NOTRACK*/\n"
                    . " UPDATE " . self::_getTrackingTable()
                    . " SET " . Util::backquote($save_to)
                    . " = CONCAT( " . Util::backquote($save_to) . ",'\n"
                    . Util::sqlAddSlashes($query) . "') ,"
                    . " `date_updated` = '" . $date . "' ";

                // If table was renamed we have to change
                // the tablename attribute in pma_tracking too
                if ($result['identifier'] == 'RENAME TABLE') {
                    $sql_query .= ', `table_name` = \''
                        . Util::sqlAddSlashes($result['tablename_after_rename'])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -903,7 +903,7 @@
 
                 // Cut off `dbname`. from query
                 $query = preg_replace(
-                    '/`' . preg_quote($dbname) . '`\s?\./',
+                    '/`' . preg_quote($dbname, '/') . '`\s?\./',
                     '',
                     $query
                 );
```
