# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5251_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5251_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 257-289 of the vulnerable file.

		@date_default_timezone_set( $t_tz );
	}
	unset( $t_tz );
}

# Cache current user's collapse API data
if( !defined( 'MANTIS_MAINTENANCE_MODE' ) ) {
	require_api( 'collapse_api.php' );
	collapse_cache_token();
}

# Load custom functions
require_api( 'custom_function_api.php' );

if( file_exists( $g_config_path . 'custom_functions_inc.php' ) ) {
	require_once( $g_config_path . 'custom_functions_inc.php' );
}

# Set HTTP response headers
require_api( 'http_api.php' );
http_all_headers();

# Push default language to speed calls to lang_get
if( !defined( 'LANG_LOAD_DISABLED' ) ) {
	require_api( 'lang_api.php' );
	lang_push( lang_get_default() );
}

# Signal plugins that the core system is loaded
if( !defined( 'PLUGINS_DISABLED' ) && !defined( 'MANTIS_MAINTENANCE_MODE' ) ) {
	require_api( 'event_api.php' );
	event_signal( 'EVENT_CORE_READY' );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -274,6 +274,7 @@
 
 # Set HTTP response headers
 require_api( 'http_api.php' );
+event_signal( 'EVENT_CORE_HEADERS' );
 http_all_headers();
 
 # Push default language to speed calls to lang_get
```
