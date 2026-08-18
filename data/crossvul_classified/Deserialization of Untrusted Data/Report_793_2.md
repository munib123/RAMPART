# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 793_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `793_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 99-128 of the vulnerable file.

    private function getFile($id, $mkdir = false)
    {
        $hash = str_replace('/', '-', base64_encode(hash('sha256', static::class.$id, true)));
        $dir = $this->directory.strtoupper($hash[0].\DIRECTORY_SEPARATOR.$hash[1].\DIRECTORY_SEPARATOR);

        if ($mkdir && !file_exists($dir)) {
            @mkdir($dir, 0777, true);
        }

        return $dir.substr($hash, 2, 20);
    }

    /**
     * @internal
     */
    public static function throwError($type, $message, $file, $line)
    {
        throw new \ErrorException($message, 0, $type, $file, $line);
    }

    public function __destruct()
    {
        if (method_exists(parent::class, '__destruct')) {
            parent::__destruct();
        }
        if (null !== $this->tmp && file_exists($this->tmp)) {
            unlink($this->tmp);
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,6 +116,16 @@
         throw new \ErrorException($message, 0, $type, $file, $line);
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
         if (method_exists(parent::class, '__destruct')) {
```
