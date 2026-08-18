# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5161_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5161_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 709-749 of the vulnerable file.

        $columnIndex, $find, $replaceWith, $charSet
    ) {
        $column = $this->_columnNames[$columnIndex];
        $sql_query = "SELECT "
            . Util::backquote($column) . ","
            . " 1," // to add an extra column that will have replaced value
            . " COUNT(*)"
            . " FROM " . Util::backquote($this->db)
            . "." . Util::backquote($this->table)
            . " WHERE " . Util::backquote($column)
            . " RLIKE '" . Util::sqlAddSlashes($find) . "' COLLATE "
            . $charSet . "_bin"; // here we
        // change the collation of the 2nd operand to a case sensitive
        // binary collation to make sure that the comparison is case sensitive
        $sql_query .= " GROUP BY " . Util::backquote($column)
            . " ORDER BY " . Util::backquote($column) . " ASC";

        $result = $this->dbi->fetchResult($sql_query, 0);

        if (is_array($result)) {
            foreach ($result as $index=>$row) {
                $result[$index][1] = preg_replace(
                    "/" . $find . "/",
                    $replaceWith,
                    $row[0]
                );
            }
        }
        return $result;
    }

    /**
     * Replaces a given string in a column with a give replacement
     *
     * @param int     $columnIndex index of the column
     * @param string  $find        string to find in the column
     * @param string  $replaceWith string to replace with
     * @param boolean $useRegex    to use Regex replace or not
     * @param string  $charSet     character set of the connection
     *
     * @return void
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -726,9 +726,22 @@
         $result = $this->dbi->fetchResult($sql_query, 0);
 
         if (is_array($result)) {
+            /* Iterate over possible delimiters to get one */
+            $delimiters = array('/', '@', '#', '~', '!', '$', '%', '^', '&', '_');
+            $found = false;
+            for ($i = 0; $i < count($delimiters); $i++) {
+                if (strpos($find, $delimiters[$i]) === false) {
+                    $found = true;
+                    break;
+                }
+            }
+            if (! $found) {
+                return false;
+            }
+            $find = $delimiters[$i] . $find . $delimiters[$i];
             foreach ($result as $index=>$row) {
                 $result[$index][1] = preg_replace(
-                    "/" . $find . "/",
+                    $find,
                     $replaceWith,
                     $row[0]
                 );
```
