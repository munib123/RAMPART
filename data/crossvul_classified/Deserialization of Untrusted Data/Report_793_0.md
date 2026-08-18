# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 793_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `793_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 64-104 of the vulnerable file.

            }
            if ('time-sensitive' === $type) {
                foreach ($namespaces as $ns) {
                    ClockMock::register($ns.'\DummyClass');
                }
            }
            if ('dns-sensitive' === $type) {
                foreach ($namespaces as $ns) {
                    DnsMock::register($ns.'\DummyClass');
                }
            }
        }
        if (self::$globallyEnabled) {
            $this->state = -2;
        } else {
            self::$globallyEnabled = true;
            if ($warn) {
                echo "Clock-mocked namespaces for SymfonyTestsListener need to be nested in a \"time-sensitive\" key. This will be enforced in Symfony 4.0.\n";
            }
        }
    }

    public function __destruct()
    {
        if (0 < $this->state) {
            file_put_contents($this->skippedFile, '<?php return '.var_export($this->isSkipped, true).';');
        }
    }

    public function globalListenerDisabled()
    {
        self::$globallyEnabled = false;
        $this->state = -1;
    }

    public function startTestSuite($suite)
    {
        if (class_exists('PHPUnit_Util_Blacklist', false)) {
            $Test = 'PHPUnit_Util_Test';
        } else {
            $Test = 'PHPUnit\Util\Test';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,6 +83,16 @@
         }
     }
 
+    public function __sleep()
+    {
+        throw new \BadMethodCallException('Cannot serialize '.__CLASS__);
+    }
+
+    public function __wakeup()
+    {
+        throw new \BadMethodCallException('Cannot unserialize '.__CLASS__);
+    }
+
     public function __destruct()
     {
         if (0 < $this->state) {
```
