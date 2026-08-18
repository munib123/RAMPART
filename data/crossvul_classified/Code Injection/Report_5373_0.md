# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 5373_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5373_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 13-54 of the vulnerable file.

 *
 * @package htsrv
 */


/**
 * Initialize:
 * TODO: Don't do a full init!
 */
require_once dirname(__FILE__).'/../conf/_config.php';
require_once $inc_path.'_main.inc.php';


param( 'plugin_ID', 'integer', true );
// fp> it is probably unnecessary complexity to handle a method here
// instead of calling handle_htsrv_action() all the time
// and letting the plugin deal with its methods internally.
param( 'method', 'string', '' );
param( 'params', 'string', null ); // serialized

if( is_null($params) )
{ // Default:
	$params = array();
}
else
{ // params given. This may result in "false", but this means that unserializing failed.
	$params = @unserialize($params);
}


if( $plugin_ID )
{
	$Plugin = & $Plugins->get_by_ID( $plugin_ID );

	if( ! $Plugin )
	{
		bad_request_die( 'Invalid Plugin! (maybe not enabled?)' );
	}


	if( method_exists( $Plugin, 'get_htsrv_methods' ) )
	{ // TODO: get_htsrv_methods is deprecated, but should stay here for transformation! (blueyed, 2006-04-27)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,13 +30,21 @@
 param( 'method', 'string', '' );
 param( 'params', 'string', null ); // serialized
 
-if( is_null($params) )
-{ // Default:
+if( is_null( $params ) )
+{	// Use empty array by default if params are not sent by request:
 	$params = array();
 }
 else
-{ // params given. This may result in "false", but this means that unserializing failed.
-	$params = @unserialize($params);
+{	// Params given:
+	if( substr( $params, 0, 2 ) == 'a:' )
+	{	// Allow to unserialize only arrays, to avoid object injection vulnerability:
+		// (This may result in "false", but this means that unserializing failed)
+		$params = @unserialize( $params );
+	}
+	else
+	{	// Restrict all non array params to empty array:
+		$params = array();
+	}
 }
 
 
```
