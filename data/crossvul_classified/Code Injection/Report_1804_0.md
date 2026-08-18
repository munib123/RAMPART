# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 1804_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1804_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 565-605 of the vulnerable file.

                                "description"   => sprintf(_("Logical AND of the integer values below that controls the debug output on every page load: %s"),
"

DEBUG_TRACE   = 1
DEBUG_LDAP    = 2
DEBUG_MYSQL   = 4
DEBUG_SHELL   = 8
DEBUG_POST    = 16
DEBUG_SESSION = 32
DEBUG_CONFIG  = 64
DEBUG_ACL     = 128
DEBUG_SI      = 256"),
                                "check"         => "gosaProperty::isInteger",
                                "migrate"       => "",
                                "group"         => "debug",
                                "mandatory"     => FALSE),

                        array(
                                "name"          => "sambaHashHook",
                                "type"          => "command",
                                "default"       => "perl -MCrypt::SmbHash -e \"print join(q[:], ntlmgen %password), $/;\"",
                                "description"   => _("Command to create Samba NT/LM hashes. Required for password synchronization if you don't use supplementary services."),
                                "check"         => "gosaProperty::isCommand",
                                "migrate"       => "",
                                "group"         => "samba",
                                "mandatory"     => FALSE),

                        array(
                                "name"          => "passwordDefaultHash",
                                "type"          => "switch",
                                "default"       => "ssha",
                                "defaults"      => "core::getPropertyValues",
                                "description"   => _("Default hash to be used for newly created user passwords."),
                                "check"         => "",
                                "migrate"       => "",
                                "group"         => "password",
                                "mandatory"     => FALSE),
                        array(
                                "name"          => "strictPasswordRules",
                                "type"          => "bool",
                                "default"       => "true",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -582,7 +582,7 @@
                         array(
                                 "name"          => "sambaHashHook",
                                 "type"          => "command",
-                                "default"       => "perl -MCrypt::SmbHash -e \"print join(q[:], ntlmgen %password), $/;\"",
+                                "default"       => "perl -MCrypt::SmbHash -e \"use MIME::Base64; print join(q[:], ntlmgen decode_base64('%password')), $/;\"",
                                 "description"   => _("Command to create Samba NT/LM hashes. Required for password synchronization if you don't use supplementary services."),
                                 "check"         => "gosaProperty::isCommand",
                                 "migrate"       => "",
```
