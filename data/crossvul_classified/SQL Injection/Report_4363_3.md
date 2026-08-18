# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4363_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4363_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 162-202 of the vulnerable file.

                ->setParameter('validate', 1)
            ;
        }

        return (float) $qb->execute()->fetchColumn();
    }

    /**
     * @param array $productIds
     * @param bool $validatedOnly
     *
     * @return array
     */
    public function getAverageGrades(array $productIds, $validatedOnly)
    {
        $sql = 'SELECT';

        $count = count($productIds);

        foreach ($productIds as $index => $id) {
            $esqID = pSQL($id);

            $sql .= ' SUM(IF(id_product = ' . $esqID . ' AND deleted = 0';
            if ($validatedOnly) {
                $sql .= ' AND validate = 1';
            }
            $sql .= ',grade, 0))';
            $sql .= ' / SUM(IF(id_product = ' . $esqID . ' AND deleted = 0';
            if ($validatedOnly) {
                $sql .= ' AND validate = 1';
            }
            $sql .= ',1, 0)) AS "' . $esqID . '"';

            if ($count - 1 > $index) {
                $sql .= ',';
            }
        }

        $sql .= ' FROM ' . $this->databasePrefix . 'product_comment';

        $query = $this->connection->prepare($sql);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -179,7 +179,7 @@
         $count = count($productIds);
 
         foreach ($productIds as $index => $id) {
-            $esqID = pSQL($id);
+            $esqID = (int) $id;
 
             $sql .= ' SUM(IF(id_product = ' . $esqID . ' AND deleted = 0';
             if ($validatedOnly) {
@@ -247,7 +247,7 @@
         $count = count($productIds);
 
         foreach ($productIds as $index => $id) {
-            $esqID = pSQL($id);
+            $esqID = (int) $id;
 
             $sql .= ' SUM(IF(id_product = ' . $esqID . ' AND deleted = 0';
             if ($validatedOnly) {
```
