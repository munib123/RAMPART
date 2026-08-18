# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4682_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4682_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-18 of the vulnerable file.

<?php

# Copyright (c) 2012 John Reese
# Licensed under the MIT license

form_security_validate( 'plugin_Source_repo_delete' );
access_ensure_global_level( plugin_config_get( 'manage_threshold' ) );

$f_repo_id = gpc_get_string( 'id' );

$t_repo = SourceRepo::load( $f_repo_id );

helper_ensure_confirmed( sprintf( plugin_lang_get( 'ensure_delete' ), $t_repo->name ), plugin_lang_get( 'delete_repository' ) );

SourceRepo::delete( $t_repo->id );

form_security_purge( 'plugin_Source_repo_delete' );
print_successful_redirect( plugin_page( 'index', true ) );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,8 @@
 
 $t_repo = SourceRepo::load( $f_repo_id );
 
-helper_ensure_confirmed( sprintf( plugin_lang_get( 'ensure_delete' ), $t_repo->name ), plugin_lang_get( 'delete_repository' ) );
+$t_message = sprintf( plugin_lang_get( 'ensure_delete' ), string_attribute( $t_repo->name ) );
+helper_ensure_confirmed( $t_message, plugin_lang_get( 'delete_repository' ) );
 
 SourceRepo::delete( $t_repo->id );
 
```
