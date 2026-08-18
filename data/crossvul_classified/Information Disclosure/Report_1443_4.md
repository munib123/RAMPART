# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1443_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1443_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 17-57 of the vulnerable file.


class Twig_Tests_Extension_SandboxTest extends \PHPUnit\Framework\TestCase
{
    protected static $params;
    protected static $templates;

    protected function setUp()
    {
        self::$params = [
            'name' => 'Fabien',
            'obj' => new FooObject(),
            'arr' => ['obj' => new FooObject()],
        ];

        self::$templates = [
            '1_basic1' => '{{ obj.foo }}',
            '1_basic2' => '{{ name|upper }}',
            '1_basic3' => '{% if name %}foo{% endif %}',
            '1_basic4' => '{{ obj.bar }}',
            '1_basic5' => '{{ obj }}',
            '1_basic6' => '{{ arr.obj }}',
            '1_basic7' => '{{ cycle(["foo","bar"], 1) }}',
            '1_basic8' => '{{ obj.getfoobar }}{{ obj.getFooBar }}',
            '1_basic9' => '{{ obj.foobar }}{{ obj.fooBar }}',
            '1_basic' => '{% if obj.foo %}{{ obj.foo|upper }}{% endif %}',
            '1_layout' => '{% block content %}{% endblock %}',
            '1_child' => "{% extends \"1_layout\" %}\n{% block content %}\n{{ \"a\"|json_encode }}\n{% endblock %}",
            '1_include' => '{{ include("1_basic1", sandboxed=true) }}',
            '1_range_operator' => '{{ (1..2)[0] }}',
        ];
    }

    /**
     * @expectedException        \Twig\Sandbox\SecurityError
     * @expectedExceptionMessage Filter "json_encode" is not allowed in "1_child" at line 3.
     */
    public function testSandboxWithInheritance()
    {
        $twig = $this->getEnvironment(true, [], self::$templates, ['block']);
        $twig->load('1_child')->render([]);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,7 +34,6 @@
             '1_basic3' => '{% if name %}foo{% endif %}',
             '1_basic4' => '{{ obj.bar }}',
             '1_basic5' => '{{ obj }}',
-            '1_basic6' => '{{ arr.obj }}',
             '1_basic7' => '{{ cycle(["foo","bar"], 1) }}',
             '1_basic8' => '{{ obj.getfoobar }}{{ obj.getFooBar }}',
             '1_basic9' => '{{ obj.foobar }}{{ obj.fooBar }}',
@@ -112,11 +111,14 @@
         }
     }
 
-    public function testSandboxUnallowedToString()
-    {
-        $twig = $this->getEnvironment(true, [], self::$templates);
-        try {
-            $twig->load('1_basic5')->render(self::$params);
+    /**
+     * @dataProvider getSandboxUnallowedToStringTests
+     */
+    public function testSandboxUnallowedToString($template)
+    {
+        $twig = $this->getEnvironment(true, [], ['index' => $template], [], ['upper'], ['FooObject' => 'getAnotherFooObject'], [], ['random']);
+        try {
+            $twig->loadTemplate('index')->render(self::$params);
             $this->fail('Sandbox throws a SecurityError exception if an unallowed method (__toString()) is called in the template');
         } catch (SecurityError $e) {
             $this->assertInstanceOf('\Twig\Sandbox\SecurityNotAllowedMethodError', $e, 'Exception should be an instance of Twig_Sandbox_SecurityNotAllowedMethodError');
@@ -125,17 +127,61 @@
         }
     }
 
-    public function testSandboxUnallowedToStringArray()
-    {
-        $twig = $this->getEnvironment(true, [], self::$templates);
-        try {
-            $twig->load('1_basic6')->render(self::$params);
-            $this->fail('Sandbox throws a SecurityError exception if an unallowed method (__toString()) is called in the template');
-        } catch (SecurityError $e) {
-            $this->assertInstanceOf('\Twig\Sandbox\SecurityNotAllowedMethodError', $e, 'Exception should be an instance of Twig_Sandbox_SecurityNotAllowedMethodError');
-            $this->assertEquals('FooObject', $e->getClassName(), 'Exception should be raised on the "FooObject" class');
-            $this->assertEquals('__tostring', $e->getMethodName(), 'Exception should be raised on the "__toString" method');
-        }
+    public function getSandboxUnallowedToStringTests()
+    {
+        return [
+            'simple' => ['{{ obj }}'],
+            'object_from_array' => ['{{ arr.obj }}'],
+            'object_chain' => ['{{ obj.anotherFooObject }}'],
+            'filter' => ['{{ obj|upper }}'],
+            'filter_from_array' => ['{{ arr.obj|upper }}'],
+            'function' => ['{{ random(obj) }}'],
+            'function_from_array' => ['{{ random(arr.obj) }}'],
+            'function_and_filter' => ['{{ random(obj|upper) }}'],
+            'function_and_filter_from_array' => ['{{ random(arr.obj|upper) }}'],
+            'object_chain_and_filter' => ['{{ obj.anotherFooObject|upper }}'],
+            'object_chain_and_function' => ['{{ random(obj.anotherFooObject) }}'],
+            'concat' => ['{{ obj ~ "" }}'],
+            'concat_again' => ['{{ "" ~ obj }}'],
+        ];
+    }
+
+    /**
+     * @dataProvider getSandboxAllowedToStringTests
+     */
+    public function testSandboxAllowedToString($template, $output)
+    {
+        $twig = $this->getEnvironment(true, [], ['index' => $template], ['set'], [], ['FooObject' => ['foo', 'getAnotherFooObject']]);
+        $this->assertEquals($output, $twig->load('index')->render(self::$params));
+    }
+
+    public function getSandboxAllowedToStringTests()
+    {
+        return [
+            'constant_test' => ['{{ obj is constant("PHP_INT_MAX") }}', ''],
+            'set_object' => ['{% set a = obj.anotherFooObject %}{{ a.foo }}', 'foo'],
+            'is_defined' => ['{{ obj.anotherFooObject is defined }}', '1'],
+            'is_null' => ['{{ obj is null }}', ''],
+            'is_sameas' => ['{{ obj is same as(obj) }}', '1'],
+            'is_sameas_from_array' => ['{{ arr.obj is same as(arr.obj) }}', '1'],
+            'is_sameas_from_another_method' => ['{{ obj.anotherFooObject is same as(obj.anotherFooObject) }}', ''],
+        ];
+    }
+
+    public function testSandboxAllowMethodToString()
+    {
+        $twig = $this->getEnvironment(true, [], self::$templates, [], [], ['FooObject' => '__toString']);
+        FooObject::reset();
+        $this->assertEquals('foo', $twig->load('1_basic5')->render(self::$params), 'Sandbox allow some methods');
+        $this->assertEquals(1, FooObject::$called['__toString'], 'Sandbox only calls method once');
+    }
+
+    public function testSandboxAllowMethodToStringDisabled()
+    {
+        $twig = $this->getEnvironment(false, [], self::$templates);
+        FooObject::reset();
+        $this->assertEquals('foo', $twig->load('1_basic5')->render(self::$params), 'Sandbox allows __toString when sandbox disabled');
+        $this->assertEquals(1, FooObject::$called['__toString'], 'Sandbox only calls method once');
     }
 
     public function testSandboxUnallowedFunction()
@@ -168,22 +214,6 @@
         FooObject::reset();
         $this->assertEquals('foo', $twig->load('1_basic1')->render(self::$params), 'Sandbox allow some methods');
         $this->assertEquals(1, FooObject::$called['foo'], 'Sandbox only calls method once');
-    }
-
-    public function testSandboxAllowMethodToString()
-    {
-        $twig = $this->getEnvironment(true, [], self::$templates, [], [], ['FooObject' => '__toString']);
-        FooObject::reset();
-        $this->assertEquals('foo', $twig->load('1_basic5')->render(self::$params), 'Sandbox allow some methods');
-        $this->assertEquals(1, FooObject::$called['__toString'], 'Sandbox only calls method once');
-    }
-
-    public function testSandboxAllowMethodToStringDisabled()
-    {
-        $twig = $this->getEnvironment(false, [], self::$templates);
-        FooObject::reset();
-        $this->assertEquals('foo', $twig->load('1_basic5')->render(self::$params), 'Sandbox allows __toString when sandbox disabled');
-        $this->assertEquals(1, FooObject::$called['__toString'], 'Sandbox only calls method once');
     }
 
     public function testSandboxAllowFilter()
@@ -326,4 +356,9 @@
 
         return 'foobar';
     }
+
+    public function getAnotherFooObject()
+    {
+        return new self();
+    }
 }
```
