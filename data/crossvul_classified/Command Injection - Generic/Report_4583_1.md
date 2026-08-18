# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in php
**Pair ID:** 4583_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4583_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<?php namespace Backend\Models;

use File;
use Lang;
use Model;
use Response;
use League\Csv\Writer as CsvWriter;
use ApplicationException;
use SplTempFileObject;

/**
 * Model used for exporting data
 *
 * @package october\backend
 * @author Alexey Bobkov, Samuel Georges
 */
abstract class ExportModel extends Model
{
    /**
     * Called when data is being exported.
     * The return value should be an array in the format of:
     *
     *   [
     *       'db_name1' => 'Some attribute value',
     *       'db_name2' => 'Another attribute value'
     *   ],
     *   [...]
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 use Model;
 use Response;
 use League\Csv\Writer as CsvWriter;
+use October\Rain\Parse\League\EscapeFormula as CsvEscapeFormula;
 use ApplicationException;
 use SplTempFileObject;
 
@@ -111,6 +112,9 @@
             $csv->setEscape($options['escape']);
         }
 
+        // Temporary until upgrading to league/csv >= 9.1.0 (will be $csv->addFormatter($formatter))
+        $formatter = new CsvEscapeFormula();
+
         /*
          * Add headers
          */
@@ -124,6 +128,10 @@
          */
         foreach ($results as $result) {
             $data = $this->matchDataToColumns($result, $columns);
+
+            // Temporary until upgrading to league/csv >= 9.1.0
+            $data = $formatter($data);
+
             $csv->insertOne($data);
         }
 
```
