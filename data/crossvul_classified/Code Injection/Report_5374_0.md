# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 5374_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5374_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 19-59 of the vulnerable file.

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

if( is_null( $params ) )
{	// Use empty array by default if params are not sent by request:
	$params = array();
}
else
{	// Params given:
	if( ( substr( $params, 0, 2 ) == 'a:' ) && ( ! preg_match( '/(;|{|})O:\+?[0-9]+:"/', $params ) ) )
	{	// Allow to unserialize only arrays + check there is no Object in the array (We NEVER want to unserialize an object)
		// (This may result in "false", but this means that unserializing failed)
		$params = @unserialize( $params );
	}
	else
	{	// Restrict all non array params to empty array:
		bad_request_die( 'Invalid params! Cannot unserialize.' );
	}
}


if( $plugin_ID )
{
	$Plugin = & $Plugins->get_by_ID( $plugin_ID );

	if( ! $Plugin )
	{
		bad_request_die( 'Invalid Plugin! (maybe not enabled?)' );
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,7 +36,7 @@
 }
 else
 {	// Params given:
-	if( ( substr( $params, 0, 2 ) == 'a:' ) && ( ! preg_match( '/(;|{|})O:\+?[0-9]+:"/', $params ) ) )
+	if( ( substr( $params, 0, 2 ) == 'a:' ) && ( ! preg_match( '/(s:\d+:"[^"]*"|i:\d+)(;|{|})O:\+?[0-9]+:"/', $params ) ) )
 	{	// Allow to unserialize only arrays + check there is no Object in the array (We NEVER want to unserialize an object)
 		// (This may result in "false", but this means that unserializing failed)
 		$params = @unserialize( $params );
```
