# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 4114_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4114_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 206-226 of the vulnerable file.

    /**
     * Gets db driver name from the db connection that is passed to the `batch()`, if it is not passed it uses
     * connection from the active record model
     * @return string|null
     */
    private function getDbDriverName()
    {
        if (isset($this->db->driverName)) {
            return $this->db->driverName;
        }

        if (!empty($this->_batch)) {
            $key = array_keys($this->_batch)[0];
            if (isset($this->_batch[$key]->db->driverName)) {
                return $this->_batch[$key]->db->driverName;
            }
        }

        return null;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -223,4 +223,15 @@
 
         return null;
     }
+
+    /**
+     * Unserialization is disabled to prevent remote code execution in case application
+     * calls unserialize() on user input containing specially crafted string.
+     * @see CVE-2020-15148
+     * @since 2.0.38
+     */
+    public function __wakeup()
+    {
+        throw new \BadMethodCallException('Cannot unserialize ' . __CLASS__);
+    }
 }
```
