# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2276_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2276_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 285-325 of the vulnerable file.


# ERROR_BUG_*
define( 'ERROR_BUG_NOT_FOUND', 1100 );
define( 'ERROR_BUG_DUPLICATE_SELF', 1101 );
# Obsoleted
#define( 'ERROR_BUG_RESOLVED_ACTION_DENIED', 1102 );
define( 'ERROR_BUG_READ_ONLY_ACTION_DENIED', 1103 );
define( 'ERROR_BUG_RESOLVE_DEPENDANTS_BLOCKING', 1104 );
define( 'ERROR_BUG_REVISION_NOT_FOUND', 1150 );

# ERROR_EMAIL_*
define( 'ERROR_EMAIL_INVALID', 1200 );
define( 'ERROR_EMAIL_DISPOSABLE', 1201 );

# ERROR_CUSTOM_FIELD_*
define( 'ERROR_CUSTOM_FIELD_NOT_FOUND', 1300 );
define( 'ERROR_CUSTOM_FIELD_NAME_NOT_UNIQUE', 1301 );
define( 'ERROR_CUSTOM_FIELD_IN_USE', 1302 );
define( 'ERROR_CUSTOM_FIELD_INVALID_VALUE', 1303 );
define( 'ERROR_CUSTOM_FIELD_INVALID_DEFINITION', 1304 );

# ERROR_LDAP_*
define( 'ERROR_LDAP_AUTH_FAILED', 1400 );
define( 'ERROR_LDAP_SERVER_CONNECT_FAILED', 1401 );
define( 'ERROR_LDAP_UPDATE_FAILED', 1402 );
define( 'ERROR_LDAP_USER_NOT_FOUND', 1403 );
define( 'ERROR_LDAP_EXTENSION_NOT_LOADED', 1404 );

# ERROR_CATEGORY_*
define( 'ERROR_CATEGORY_DUPLICATE', 1500 );
define( 'ERROR_CATEGORY_NO_ACTION', 1501 );
define( 'ERROR_CATEGORY_NOT_FOUND', 1502 );
define( 'ERROR_CATEGORY_NOT_FOUND_FOR_PROJECT', 1503 );

# ERROR_VERSION_*
define( 'ERROR_VERSION_DUPLICATE', 1600 );
define( 'ERROR_VERSION_NOT_FOUND', 1601 );

# ERROR_SPONSORSHIP_*
define( 'ERROR_SPONSORSHIP_NOT_ENABLED', 1700 );
define( 'ERROR_SPONSORSHIP_NOT_FOUND', 1701 );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -302,6 +302,7 @@
 define( 'ERROR_CUSTOM_FIELD_IN_USE', 1302 );
 define( 'ERROR_CUSTOM_FIELD_INVALID_VALUE', 1303 );
 define( 'ERROR_CUSTOM_FIELD_INVALID_DEFINITION', 1304 );
+define( 'ERROR_CUSTOM_FIELD_NOT_LINKED_TO_PROJECT', 1305 );
 
 # ERROR_LDAP_*
 define( 'ERROR_LDAP_AUTH_FAILED', 1400 );
```
