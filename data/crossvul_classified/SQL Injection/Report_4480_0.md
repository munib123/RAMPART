# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4480_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4480_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 218-258 of the vulnerable file.


            if (!in_array($name, $this->getCollectionNames())) {
                $this->createCollection($name);
            }

            $this->collections[$name] = new Collection($name, $this);
        }

        return $this->collections[$name];
    }

    public function __get($collection) {

        return $this->selectCollection($collection);
    }
}


class UtilArrayQuery {

    public static function buildCondition($criteria, $concat = ' && ') {

        $fn = [];

        foreach ($criteria as $key => $value) {

            switch($key) {

                case '$and':

                    $_fn = [];

                    foreach ($value as $v) {
                        $_fn[] = self::buildCondition($v, ' && ');
                    }

                    $fn[] = '('.\implode(' && ', $_fn).')';

                    break;
                case '$or':

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -235,6 +235,12 @@
 
 class UtilArrayQuery {
 
+    protected static $closures = [];
+
+    public static function closureCall($uid, $doc) {
+        return call_user_func_array(self::$closures[$uid], [$doc]);
+    }
+
     public static function buildCondition($criteria, $concat = ' && ') {
 
         $fn = [];
@@ -268,10 +274,15 @@
 
                 case '$where':
 
-                    if (\is_callable($value)) {
-
-                        // need implementation
+                    if (\is_string($value) || !\is_callable($value)) {
+                        throw new \InvalidArgumentException($key.' Function should be callable');
                     }
+
+                    $uid = \uniqid('mongoliteCallable').bin2hex(random_bytes(5));
+
+                    self::$closures[$uid] = $value;
+
+                    $fn[] = '\\MongoLite\\UtilArrayQuery::closureCall("'.$uid.'", $document)';
 
                     break;
 
@@ -426,14 +437,6 @@
                 $r = $a % $b[0] == $b[1] ?? 0;
                 break;
 
-            case '$func' :
-            case '$fn' :
-            case '$f' :
-                if (\is_string($b) || !\is_callable($b))
-                    throw new \InvalidArgumentException('Function should be callable');
-                $r = $b($a);
-                break;
-
             case '$exists':
                 $r = $b ? !\is_null($a) : \is_null($a);
                 break;
```
