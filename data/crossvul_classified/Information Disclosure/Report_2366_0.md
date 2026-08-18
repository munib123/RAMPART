# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2366_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2366_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 77-122 of the vulnerable file.

	config_get_global( 'db_username' ), config_get_global( 'db_password' ),
	config_get_global( 'database_name' ) );

if( false == $result ) {
	echo "Opening connection to database " .
		config_get_global( 'database_name' ) .
		" on host " . config_get_global( 'hostname' ) .
		" with username " . config_get_global( 'db_username' ) .
		" failed: " . db_error_msg() . "\n";
	exit( 1 );
}

# TODO: Enhance this check to support the mode where this script is called on an empty database.
# check to see if the new installer was used
if ( -1 == config_get( 'database_version', -1 ) ) {
        echo "Upgrade from the current installed MantisBT version is no longer supported.  If you are using MantisBT version older than 1.0.0, then upgrade to v1.0.0 first.";
        exit( 1 );
}

# read control variables with defaults
$f_hostname = gpc_get( 'hostname', config_get( 'hostname', 'localhost' ) );
$f_db_type = gpc_get( 'db_type', config_get( 'db_type', '' ) );
$f_database_name = gpc_get( 'database_name', config_get( 'database_name', 'bugtrack' ) );
$f_db_username = gpc_get( 'db_username', config_get( 'db_username', '' ) );
$f_db_password = gpc_get( 'db_password', config_get( 'db_password', '' ) );
$f_db_exists = gpc_get_bool( 'db_exists', false );

# install the tables
if ( !preg_match( '/^[a-zA-Z0-9_]+$/', $f_db_type ) ||
     !file_exists( dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'library' . DIRECTORY_SEPARATOR . 'adodb' . DIRECTORY_SEPARATOR . 'drivers' . DIRECTORY_SEPARATOR . 'adodb-' . $f_db_type . '.inc.php' ) ) {
	echo 'Invalid db type ' . htmlspecialchars( $f_db_type ) . '.';
	exit;
}

$GLOBALS['g_db_type'] = $f_db_type; # database_api references this
require_once( dirname( __FILE__ ) . DIRECTORY_SEPARATOR . 'schema.php' );
$g_db = ADONewConnection( $f_db_type );

echo "\nPost 1.0 schema changes\n";
echo "Connecting to database... ";
$t_result = @$g_db->Connect( $f_hostname, $f_db_username, $f_db_password, $f_database_name );

if( false == $t_result ) {
	echo "Failed.\n";
	exit( 1 );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,27 +94,22 @@
 }
 
 # read control variables with defaults
-$f_hostname = gpc_get( 'hostname', config_get( 'hostname', 'localhost' ) );
-$f_db_type = gpc_get( 'db_type', config_get( 'db_type', '' ) );
-$f_database_name = gpc_get( 'database_name', config_get( 'database_name', 'bugtrack' ) );
-$f_db_username = gpc_get( 'db_username', config_get( 'db_username', '' ) );
-$f_db_password = gpc_get( 'db_password', config_get( 'db_password', '' ) );
-$f_db_exists = gpc_get_bool( 'db_exists', false );
+$t_db_type = config_get_global( 'db_type' );
 
 # install the tables
-if ( !preg_match( '/^[a-zA-Z0-9_]+$/', $f_db_type ) ||
-     !file_exists( dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'library' . DIRECTORY_SEPARATOR . 'adodb' . DIRECTORY_SEPARATOR . 'drivers' . DIRECTORY_SEPARATOR . 'adodb-' . $f_db_type . '.inc.php' ) ) {
-	echo 'Invalid db type ' . htmlspecialchars( $f_db_type ) . '.';
+if( !preg_match( '/^[a-zA-Z0-9_]+$/', $f_db_type ) ||
+	!file_exists( dirname( dirname( __FILE__ ) ) . '/library/adodb/drivers/adodb-' . $t_db_type . '.inc.php' ) ) {
+	echo 'Invalid db type ' . htmlspecialchars( $t_db_type ) . '.';
 	exit;
 }
 
-$GLOBALS['g_db_type'] = $f_db_type; # database_api references this
-require_once( dirname( __FILE__ ) . DIRECTORY_SEPARATOR . 'schema.php' );
-$g_db = ADONewConnection( $f_db_type );
+$GLOBALS['g_db_type'] = $t_db_type; # database_api references this
+require_once( dirname( __FILE__ ) . '/schema.php' );
+$g_db = ADONewConnection( $t_db_type );
 
 echo "\nPost 1.0 schema changes\n";
 echo "Connecting to database... ";
-$t_result = @$g_db->Connect( $f_hostname, $f_db_username, $f_db_password, $f_database_name );
+$t_result = @$g_db->Connect( config_get_global( 'hostname' ), config_get_global( 'db_username' ), config_get_global( 'db_password' ), config_get_global( 'database_name' ) );
 
 if( false == $t_result ) {
 	echo "Failed.\n";
```
