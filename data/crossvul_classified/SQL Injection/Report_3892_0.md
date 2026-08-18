# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3892_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3892_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 427-467 of the vulnerable file.

     * $member->readDataByColumn(array('mem_rol_id' => $roleId, 'mem_usr_id' => $userId));
     * ```
     * @see TableAccess#readData
     * @see TableAccess#readDataById
     */
    public function readDataByColumns(array $columnArray)
    {
        // initialize the object, so that all fields are empty
        $this->clear();

        if (count($columnArray) === 0)
        {
            return false;
        }

        $sqlWhereCondition = '';

        // add every array element as a sql condition to the condition string
        foreach ($columnArray as $columnName => $columnValue)
        {
            $sqlWhereCondition .= ' AND ' . $columnName . ' = \'' . $columnValue . '\' ';
        }

        // call method to read data out of database
        $returnCode = $this->readData($sqlWhereCondition);

        // save the array fields in the object
        if (!$returnCode)
        {
            foreach ($columnArray as $columnName => $columnValue)
            {
                $this->setValue($columnName, $columnValue);
            }
        }

        return $returnCode;
    }

    /**
     * Save all changed columns of the recordset in table of database. Therefore the class remembers if it's
     * a new record or if only an update is necessary. The update statement will only update the changed columns.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -444,11 +444,11 @@
         // add every array element as a sql condition to the condition string
         foreach ($columnArray as $columnName => $columnValue)
         {
-            $sqlWhereCondition .= ' AND ' . $columnName . ' = \'' . $columnValue . '\' ';
+            $sqlWhereCondition .= ' AND ' . $columnName . ' = ? ';
         }
 
         // call method to read data out of database
-        $returnCode = $this->readData($sqlWhereCondition);
+        $returnCode = $this->readData($sqlWhereCondition, array_values($columnArray));
 
         // save the array fields in the object
         if (!$returnCode)
```
