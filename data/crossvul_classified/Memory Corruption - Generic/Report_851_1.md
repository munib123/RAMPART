# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in php
**Pair ID:** 851_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `851_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```php
Lines 44-76 of the vulnerable file.


  # setM
  $after['newKey'] = array();
  var_dump($after);

  # unsetm
  foreach($after as $k => $v) {
    unset($after[$k]);
  }
  var_dump($after);
}

function testKeyTypes() {
  apc_add("keysarray", array(2 => 'two', '3' => 'three'));
  $arr = __hhvm_intrinsics\apc_fetch_no_check("keysarray");
  foreach (array(2, 3, '2', '3') as $k) {
    try { var_dump($arr[$k]); } catch (Exception $e) { echo $e->getMessage()."\n"; }
  }
}

<<__EntryPoint>> function main(): void {
  testApc(array(7, 4, 1776));
  testApc(array("sv0", "sv1"));
  testApc(array("sk0" => "sv0", "sk1" => "sv1"));

  // Also check that foreign arrays work for indirect calls
  apc_store('foo', array("a"));
  $a = __hhvm_intrinsics\apc_fetch_no_check('foo');
  $b = call_user_func_array(fun("strtoupper"), $a);
  var_dump($b);

  testKeyTypes();
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,6 +61,16 @@
   }
 }
 
+function testInvalidKeys() {
+    // Reject keys with null bytes
+    apc_add("bar\x00baz", 10);
+    apc_store("test\x00xyz", "hello");
+    apc_store(array("validkey" => "validvalue", "invalid\x00key" => "value"));
+    foreach (array('bar', 'test', 'validkey', 'invalid') as $k) {
+        var_dump(__hhvm_intrinsics\apc_fetch_no_check($k));
+    }
+}
+
 <<__EntryPoint>> function main(): void {
   testApc(array(7, 4, 1776));
   testApc(array("sv0", "sv1"));
@@ -73,4 +83,5 @@
   var_dump($b);
 
   testKeyTypes();
+  testInvalidKeys();
 }
```
