# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 4433_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4433_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 1261-1301 of the vulnerable file.

                'Security' => array(
                        'branch' => 1,
                        'disable_form_security' => array(
                            'level' => 0,
                            'description' => __('Disabling this setting will remove all form tampering protection. Do not set this setting pretty much ever. You were warned.'),
                            'value' => false,
                            'errorMessage' => 'This setting leaves your users open to CSRF attacks. Do not please consider disabling this setting.',
                            'test' => 'testBoolFalse',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'salt' => array(
                                'level' => 0,
                                'description' => __('The salt used for the hashed passwords. You cannot reset this from the GUI, only manually from the settings.php file. Keep in mind, this will invalidate all passwords in the database.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testSalt',
                                'type' => 'string',
                                'editable' => false,
                                'redacted' => true
                        ),
                        'syslog' => array(
                            'level' => 0,
                            'description' => __('Enable this setting to pass all audit log entries directly to syslog. Keep in mind, this is verbose and will include user, organisation, event data.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'do_not_log_authkeys' => array(
                            'level' => 0,
                            'description' => __('If enabled, any authkey will be replaced by asterisks in Audit log.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'email_otp_enabled' => array(
                                'level'=> 2,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1279,6 +1279,23 @@
                                 'editable' => false,
                                 'redacted' => true
                         ),
+                        'rest_client_enable_arbitrary_urls' => array(
+                            'level' => 0,
+                            'description' => __('Enable this setting if you wish for users to be able to query any arbitrary URL via the rest client. Keep in mind that queries are executed by the MISP server, so internal IPs in your MISP\'s network may be reachable.'),
+                            'value' => false,
+                            'errorMessage' => '',
+                            'test' => 'testBool',
+                            'type' => 'boolean',
+                            'null' => true
+                        ),
+                        'rest_client_baseurl' => array(
+                            'level' => 1,
+                            'description' => __('If left empty, the baseurl of your MISP is used. However, in some instances (such as port-forwarded VM installations) this will not work. You can override the baseurl with a url through which your MISP can reach itself (typically https://127.0.0.1 would work).'),
+                            'value' => false,
+                            'errorMessage' => '',
+                            'test' => null,
+                            'type' => 'string',
+                        ),
                         'syslog' => array(
                             'level' => 0,
                             'description' => __('Enable this setting to pass all audit log entries directly to syslog. Keep in mind, this is verbose and will include user, organisation, event data.'),
```
