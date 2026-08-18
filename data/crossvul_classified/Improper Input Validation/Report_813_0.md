# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 813_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `813_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 59-99 of the vulnerable file.

    /**
     * The response of the last sent SMTP command.
     *
     * @var array
     */
    protected $_lastResponse = [];

    /**
     * Destructor
     *
     * Tries to disconnect to ensure that the connection is being
     * terminated properly before the socket gets closed.
     */
    public function __destruct()
    {
        try {
            $this->disconnect();
        } catch (Exception $e) {
            // avoid fatal error on script termination
        }
    }

    /**
     * Connect to the SMTP server.
     *
     * This method tries to connect only in case there is no open
     * connection available already.
     *
     * @return void
     */
    public function connect()
    {
        if (!$this->connected()) {
            $this->_connect();
            $this->_auth();
        }
    }

    /**
     * Check whether an open connection to the SMTP server is available.
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,6 +76,18 @@
         } catch (Exception $e) {
             // avoid fatal error on script termination
         }
+    }
+
+    /**
+     * Unserialize handler.
+     *
+     * Ensure that the socket property isn't reinitialized in a broken state.
+     *
+     * @return void
+     */
+    public function __wakeup()
+    {
+        $this->_socket = null;
     }
 
     /**
```
