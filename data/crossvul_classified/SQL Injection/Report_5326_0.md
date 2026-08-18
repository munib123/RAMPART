# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5326_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5326_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

    $total_new = 0;

    include_once('../exponent.php');
    if (php_sapi_name() == 'cli') {
        $nl = "\n";
        if (!empty($_SERVER['argc'])) for ($ac = 1; $ac < $_SERVER['argc']; $ac++) {
            if ($_SERVER['argv'][$ac] == '-v') {
                $verbose = true;
            } elseif (!empty($_SERVER['argv'][$ac])) {
                $version_title = $_SERVER['argv'][$ac];
                $version = $db->selectValue('help_version', 'id', 'version="' . $_SERVER['argv'][$ac] . '"');
            }
        }
    } else {
        $nl = '<br>';
        if (!empty($_GET['verbose'])) {
            $verbose = true;
        }
        if (!empty($_GET['version'])) {
            $version_title = $_GET['version'];
            $version = $db->selectValue('help_version', 'id', 'version="' . expString::sanitize($_GET['version']) . '"');
        }
    }
    /**
     * find_help.php - attempts to auto-check all ExponentCMS help links
     * by collecting them and checking them against the doc.exponentcms.org db tables
     */
    print $nl . "Checking the Exponent Help System!" . $nl . $nl;
    print "Grabbing links from the folders!" . $nl;
    parse_files('..', false);
    $filelist = array('../cron', '../framework', '../install', '../themes');
    foreach ($filelist as $file) {
        parse_files($file);
    }

    print $nl . "Completed grabbing " . $total_new . " Total Help Links!" . $nl . $nl;
    if (empty($version)) {
        $version = $db->selectValue('help_version', 'id', 'is_current=1');
        $version_title = 'Current';
    }
    print "Using Help Version - " . $version_title . "!" . $nl . $nl;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
         }
         if (!empty($_GET['version'])) {
             $version_title = $_GET['version'];
-            $version = $db->selectValue('help_version', 'id', 'version="' . expString::sanitize($_GET['version']) . '"');
+            $version = $db->selectValue('help_version', 'id', 'version="' . expString::escape($_GET['version']) . '"');
         }
     }
     /**
```
