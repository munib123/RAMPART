# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2453_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2453_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1277-1317 of the vulnerable file.

                            'type' => 'boolean',
                            'null' => true
                        ),
                        'sanitise_attribute_on_delete' => array(
                            'level' => 1,
                            'description' => __('Enabling this setting will sanitise the contents of an attribute on a soft delete'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'hide_organisation_index_from_users' => array(
                            'level' => 1,
                            'description' => __('Enabling this setting will block the organisation index from being visible to anyone besides site administrators on the current instance. Keep in mind that users can still see organisations that produce data via events, proposals, event history log entries, etc.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'allow_unsafe_apikey_named_param' => array(
                            'level' => 0,
                            'description' => __('Allows passing the API key via the named url parameter "apikey" - highly recommended not to enable this, but if you have some dodgy legacy tools that cannot pass the authorization header it can work as a workaround. Again, only use this as a last resort.'),
                            'value' => false,
                            'errorMessage' => __('You have enabled the passing of API keys via URL parameters. This is highly recommended against, do you really want to reveal APIkeys in your logs?...'),
                            'test' => 'testBoolFalse',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'allow_cors' => array(
                            'level' => 1,
                            'description' => __('Allow cross-origin requests to this instance, matching origins given in Security.cors_origins. Set to false to totally disable'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'cors_origins' => array(
                            'level' => 1,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1295,6 +1295,16 @@
                             'type' => 'boolean',
                             'null' => true
                         ),
+                        'disable_local_feed_access' => array(
+                                'level' => 0,
+                                'description' => __('Disabling this setting will allow the creation/modification of local feeds (as opposed to network feeds). Enabling this setting will restrict feed sources to be network based only. When disabled, keep in mind that a malicious site administrator could get access to any arbitrary file on the system that the apache user has access to. Make sure that proper safe-guards are in place. This setting can only be modified via the CLI.'),
+                                'value' => false,
+                                'errorMessage' => '',
+                                'test' => 'testBool',
+                                'type' => 'boolean',
+                                'null' => true,
+                                'cli_only' => 1
+                        ),
                         'allow_unsafe_apikey_named_param' => array(
                             'level' => 0,
                             'description' => __('Allows passing the API key via the named url parameter "apikey" - highly recommended not to enable this, but if you have some dodgy legacy tools that cannot pass the authorization header it can work as a workaround. Again, only use this as a last resort.'),
```
