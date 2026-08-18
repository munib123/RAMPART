# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3101_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3101_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 19-59 of the vulnerable file.


/**
 * Release date (ISO)
 * @global string
 */
$app_date = '2017-01-11';

/**
 * Long version string for checking differences
 */
$app_version_long = $app_version.'-'.$app_date;

/**
 * This is used to check if the database is up to date.
 *
 * This will be incrememented by 5 with each change in {@link upgrade_b2evo_tables()}
 * in order to leave space for maintenance releases.
 *
 * {@internal Before changing this in CVS, it should be discussed! }}
 */
$new_db_version = 11810;

/**
 * Minimum PHP version required for b2evolution to function properly. It will contain each module own minimum PHP version as well.
 * @global array
 */
$required_php_version = array( 'application' => '5.2' );

/**
 * Minimum MYSQL version required for b2evolution to function properly. It will contain each module own minimum MYSQL version as well.
 * @global array
 */
$required_mysql_version = array( 'application' => '5.0.3' );

/**
 * Is displayed on the login screen:
 */
$app_footer_text = '<a href="http://b2evolution.net/" title="visit b2evolution\'s website"><strong>b2evolution '.$app_version.'</strong></a>
		&ndash;
		<a href="http://b2evolution.net/about/gnu-gpl-license" class="nobr">GPL License</a>';

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,7 +36,7 @@
  *
  * {@internal Before changing this in CVS, it should be discussed! }}
  */
-$new_db_version = 11810;
+$new_db_version = 11815;
 
 /**
  * Minimum PHP version required for b2evolution to function properly. It will contain each module own minimum PHP version as well.
```
