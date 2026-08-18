# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4566_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4566_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 128-168 of the vulnerable file.

    public function setDateFormat($value)
    {
        if (!is_string($value)) {
            throw new PrestaShopException('Date format must be a string');
        }

        $this->_date_format = $value;

        return $this;
    }

    public function getDateFormat()
    {
        if (!isset($this->_date_format)) {
            $this->_date_format = self::DEFAULT_DATE_FORMAT;
        }

        return $this->_date_format;
    }

    public function setDateFrom($value)
    {
        if (!isset($value) || $value == '') {
            $value = date('Y-m-d', strtotime('-31 days'));
        }

        if (!is_string($value)) {
            throw new PrestaShopException('Date must be a string');
        }

        $this->_date_from = $value;

        return $this;
    }

    public function getDateFrom()
    {
        if (!isset($this->_date_from)) {
            $this->_date_from = date('Y-m-d', strtotime('-31 days'));
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -145,17 +145,17 @@
         return $this->_date_format;
     }
 
-    public function setDateFrom($value)
-    {
-        if (!isset($value) || $value == '') {
-            $value = date('Y-m-d', strtotime('-31 days'));
+    public function setDateFrom($value = '')
+    {
+        if (empty($value)) {
+            $value = strtotime('-31 days');
         }
 
         if (!is_string($value)) {
             throw new PrestaShopException('Date must be a string');
         }
 
-        $this->_date_from = $value;
+        $this->_date_from = date('Y-m-d', strtotime($value));
 
         return $this;
     }
@@ -163,23 +163,23 @@
     public function getDateFrom()
     {
         if (!isset($this->_date_from)) {
-            $this->_date_from = date('Y-m-d', strtotime('-31 days'));
+            $this->setDateFrom();
         }
 
         return $this->_date_from;
     }
 
-    public function setDateTo($value)
-    {
-        if (!isset($value) || $value == '') {
-            $value = date('Y-m-d');
+    public function setDateTo($value = '')
+    {
+        if (empty($value)) {
+            $value = strtotime('-31 days');
         }
 
         if (!is_string($value)) {
             throw new PrestaShopException('Date must be a string');
         }
 
-        $this->_date_to = $value;
+        $this->_date_to = date('Y-m-d', strtotime($value));
 
         return $this;
     }
@@ -187,7 +187,7 @@
     public function getDateTo()
     {
         if (!isset($this->_date_to)) {
-            $this->_date_to = date('Y-m-d');
+            $this->setDateTo();
         }
 
         return $this->_date_to;
```
