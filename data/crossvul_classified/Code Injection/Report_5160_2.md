# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5160_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5160_2`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 1489-1529 of the vulnerable file.


            // Convert end of line chars to one that we want (note that MySQL
            // doesn't return query it will accept in all cases)
            if (mb_strpos($create_query, "(\r\n ")) {
                $create_query = str_replace("\r\n", $crlf, $create_query);
            } elseif (mb_strpos($create_query, "(\n ")) {
                $create_query = str_replace("\n", $crlf, $create_query);
            } elseif (mb_strpos($create_query, "(\r ")) {
                $create_query = str_replace("\r", $crlf, $create_query);
            }

            /*
             * Drop database name from VIEW creation.
             *
             * This is a bit tricky, but we need to issue SHOW CREATE TABLE with
             * database name, but we don't want name to show up in CREATE VIEW
             * statement.
             */
            if ($view) {
                $create_query = preg_replace(
                    '/' . preg_quote(Util::backquote($db)) . '\./',
                    '',
                    $create_query
                );
            }

            // Substitute aliases in `CREATE` query.
            $create_query = $this->replaceWithAliases(
                $create_query,
                $aliases,
                $db,
                $table,
                $flag
            );

            // One warning per view.
            if ($flag && $view) {
                $warning = $this->_exportComment()
                    . $this->_exportComment(
                        __('It appears your database uses views;')
                    )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1506,7 +1506,7 @@
              */
             if ($view) {
                 $create_query = preg_replace(
-                    '/' . preg_quote(Util::backquote($db)) . '\./',
+                    '/' . preg_quote(Util::backquote($db), '/') . '\./',
                     '',
                     $create_query
                 );
```
