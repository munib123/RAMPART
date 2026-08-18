# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in php
**Pair ID:** 4583_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4583_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```php
Lines 1-34 of the vulnerable file.

<?php namespace Backend\Behaviors;

use Str;
use Lang;
use View;
use Response;
use Backend;
use BackendAuth;
use Backend\Classes\ControllerBehavior;
use Backend\Behaviors\ImportExportController\TranscodeFilter;
use Illuminate\Database\Eloquent\MassAssignmentException;
use League\Csv\Reader as CsvReader;
use League\Csv\Writer as CsvWriter;
use ApplicationException;
use SplTempFileObject;
use Exception;

/**
 * Adds features for importing and exporting data.
 *
 * This behavior is implemented in the controller like so:
 *
 *     public $implement = [
 *         'Backend.Behaviors.ImportExportController',
 *     ];
 *
 *     public $importExportConfig = 'config_import_export.yaml';
 *
 * The `$importExportConfig` property makes reference to the configuration
 * values as either a YAML file, located in the controller view directory,
 * or directly as a PHP array.
 *
 * @package october\backend
 * @author Alexey Bobkov, Samuel Georges
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
 use Illuminate\Database\Eloquent\MassAssignmentException;
 use League\Csv\Reader as CsvReader;
 use League\Csv\Writer as CsvWriter;
+use October\Rain\Parse\League\EscapeFormula as CsvEscapeFormula;
 use ApplicationException;
 use SplTempFileObject;
 use Exception;
@@ -624,6 +625,9 @@
         $csv->setEnclosure($options['enclosure']);
         $csv->setEscape($options['escape']);
 
+        // Temporary until upgrading to league/csv >= 9.1.0 (will be $csv->addFormatter($formatter))
+        $formatter = new CsvEscapeFormula();
+
         /*
          * Add headers
          */
@@ -657,6 +661,10 @@
                 }
                 $record[] = $value;
             }
+
+            // Temporary until upgrading to league/csv >= 9.1.0
+            $record = $formatter($record);
+
             $csv->insertOne($record);
         }
 
```
