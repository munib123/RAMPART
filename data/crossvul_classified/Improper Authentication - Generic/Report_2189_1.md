# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 2189_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2189_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 64-104 of the vulnerable file.

                                          self::$ldapcfg['server']['hostspec']),
                      'port'      => self::$ldapcfg['server']['port'],
                      'binddn'    => self::$ldapcfg['server']['binddn'],
                      'bindpw'    => self::$ldapcfg['server']['bindpw']);
        $ldap = new Horde_Ldap($lcfg);
    }

    /**
     * Tests if the server can connect and bind anonymously, if supported.
     */
    public function testConnectAndAnonymousBind()
    {
        if (!self::$ldapcfg['capability']['anonymous']) {
            $this->markTestSkipped('Server does not support anonymous bind');
        }

        // Simple working connect and anonymous bind.
        $lcfg = array('hostspec' => self::$ldapcfg['server']['hostspec'],
                      'port'     => self::$ldapcfg['server']['port']);
        $ldap = new Horde_Ldap($lcfg);
    }

    /**
     * Tests startTLS() if server supports it.
     */
    public function testStartTLS()
    {
        if (!self::$ldapcfg['capability']['tls']) {
            $this->markTestSkipped('Server does not support TLS');
        }

        // Simple working connect and privileged bind.
        $lcfg = array('starttls' => true) + self::$ldapcfg['server'];
        $ldap = new Horde_Ldap($lcfg);
    }

    /**
     * Test if adding and deleting a fresh entry works.
     */
    public function testAdd()
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,6 +81,19 @@
         $lcfg = array('hostspec' => self::$ldapcfg['server']['hostspec'],
                       'port'     => self::$ldapcfg['server']['port']);
         $ldap = new Horde_Ldap($lcfg);
+    }
+
+    /**
+     * Tests if the server can connect and bind, but not rebind with empty
+     * password.
+     *
+     * @expectedException Horde_Ldap_Exception
+     */
+    public function testConnectAndEmptyRebind()
+    {
+        // Simple working connect and privileged bind.
+        $ldap = new Horde_Ldap(self::$ldapcfg['server']);
+        $ldap->bind(self::$ldapcfg['server']['binddn'], '');
     }
 
     /**
```
