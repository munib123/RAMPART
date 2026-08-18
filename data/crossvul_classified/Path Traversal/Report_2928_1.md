# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 2928_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2928_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 41-81 of the vulnerable file.

 * @param string $socket
 * @return mysqli
 * @throws DatabaseConnectException
 */
function dbConnect($host = null, $user = '', $password = '', $database = '', $port = null, $socket = null)
{
    global $config, $database_link;

    if (dbIsConnected()) {
        return $database_link;
    }

    $host = empty($host) ? $config['db_host'] : $host;
    $user = empty($user) ? $config['db_user'] : $user;
    $password = empty($password) ? $config['db_pass'] : $password;
    $database = empty($database) ? $config['db_name'] : $database;
    $port = empty($port) ? $config['db_port'] : $port;
    $socket = empty($socket) ? $config['db_socket'] : $socket;

    $database_link = mysqli_connect('p:' . $host, $user, $password, null, $port, $socket);
    if ($database_link === false) {
        $error = mysqli_connect_error();
        if ($error == 'No such file or directory') {
            $error = 'Could not connect to ' . $host;
        }
        throw new DatabaseConnectException($error);
    }

    $database_db = mysqli_select_db($database_link, $config['db_name']);
    if (!$database_db) {
        $db_create_sql = "CREATE DATABASE " . $config['db_name'] . " CHARACTER SET utf8 COLLATE utf8_unicode_ci";
        mysqli_query($database_link, $db_create_sql);
        $database_db = mysqli_select_db($database_link, $database);
    }

    if (!$database_db) {
        throw new DatabaseConnectException("Could not select database: $database. " . mysqli_error($database_link));
    }

    dbQuery("SET NAMES 'utf8'");
    dbQuery("SET CHARACTER SET 'utf8'");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,6 +58,7 @@
     $socket = empty($socket) ? $config['db_socket'] : $socket;
 
     $database_link = mysqli_connect('p:' . $host, $user, $password, null, $port, $socket);
+    mysqli_options($database_link, MYSQLI_OPT_LOCAL_INFILE, false);
     if ($database_link === false) {
         $error = mysqli_connect_error();
         if ($error == 'No such file or directory') {
```
