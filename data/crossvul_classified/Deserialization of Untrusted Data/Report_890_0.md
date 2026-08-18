# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 890_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `890_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 3059-3099 of the vulnerable file.

    }

    public function testForPath($value)
    {
        if ($value === '') {
            return true;
        }
        if (preg_match('@^\/?(([a-z0-9_.]+[a-z0-9_.\-.\:]*[a-z0-9_.\-.\:]|[a-z0-9_.])+\/?)+$@i', $value)) {
            return true;
        }
        return 'Invalid characters in the path.';
    }

    public function beforeHookBinExec($setting, $value)
    {
        return $this->testForBinExec($value);
    }

    public function testForBinExec($value)
    {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($value === '') {
            return true;
        }
        if (is_executable($value)) {
            if (finfo_file($finfo, $value) == "application/x-executable" || finfo_file($finfo, $value) == "application/x-sharedlib") {
                finfo_close($finfo);
                return true;
            } else {
                return 'Binary file not executable. It is of type: ' . finfo_file($finfo, $value);
            }
        } else {
            return false;
        }
    }

    public function testForWritableDir($value)
    {
        if (!is_dir($value)) {
            return 'Not a valid directory.';
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3076,6 +3076,9 @@
 
     public function testForBinExec($value)
     {
+        if (substr($value, 0, 7) === "phar://") {
+            return 'Phar protocol not allowed.';
+        }
         $finfo = finfo_open(FILEINFO_MIME_TYPE);
         if ($value === '') {
             return true;
@@ -3094,6 +3097,9 @@
 
     public function testForWritableDir($value)
     {
+        if (substr($value, 0, 7) === "phar://") {
+            return 'Phar protocol not allowed.';
+        }
         if (!is_dir($value)) {
             return 'Not a valid directory.';
         }
```
