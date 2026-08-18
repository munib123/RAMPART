# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3113_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3113_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 651-691 of the vulnerable file.

 * However if the following values are set to non empty, the admin will not be able to customize these values.
 */
$force_regexp_filename = '';
$force_regexp_dirname = '';

/**
 * The maximum length of a file name. On new uploads file names with more characters are not allowed.
 */
$filename_max_length = 64;

/**
 * The maximum length of a file absolute path. Creating folders/files with longer path then this value is not allowed.
 * Note: 247 is the max length of an absolute path what the php file operation functions can handle on windows.
 * On unix systems the file path length is not an issue, so there we can allow a higher value.
 * The OS independent max length is 767, because that is what b2evolution can handle correctly.
 */
$dirpath_max_length = ( ( ( strtoupper( substr( PHP_OS, 0, 3 ) ) ) === 'WIN' ) ? ( 247 - 35 /* the maximum additional path length because of the _evocache folder */ ) : 767 ) - $filename_max_length;


/**
 * XMLRPC logging. Set this to 1 to log XMLRPC calls received by this server (into /xmlsrv/xmlrpc.log).
 *
 * Default: 0
 *
 * @global int $debug_xmlrpc_logging
 */
$debug_xmlrpc_logging = 0;


/**
 * Seconds after which a scheduled task is considered to be timed out.
 */
$cron_timeout_delay = 1800; // 30 minutes


/**
 * Password change request delay in seconds. Only one email can be requested for one login or email address in each x seconds defined below.
 */
$pwdchange_request_delay = 300; // 5 minutes


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -665,6 +665,13 @@
  * The OS independent max length is 767, because that is what b2evolution can handle correctly.
  */
 $dirpath_max_length = ( ( ( strtoupper( substr( PHP_OS, 0, 3 ) ) ) === 'WIN' ) ? ( 247 - 35 /* the maximum additional path length because of the _evocache folder */ ) : 767 ) - $filename_max_length;
+
+
+/**
+ * Allow double dots in file names
+ * Use TRUE if you want to allow ".." in file and directory names like "..filename" or "dir..name"
+ */
+$filemanager_allow_dotdot_in_filenames = false;
 
 
 /**
```
