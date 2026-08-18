# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 791_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `791_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 176-216 of the vulnerable file.

        $builder->set('bar', $bar = new \stdClass());

        $this->assertSame($bar, $builder->get('bar'), '->get() returns the service associated with the id');
    }

    public function testRegisterDoesNotOverrideExistingService()
    {
        $builder = new ContainerBuilder();
        $builder->set('bar', $bar = new \stdClass());
        $builder->register('bar', 'stdClass');

        $this->assertSame($bar, $builder->get('bar'), '->get() returns the service associated with the id even if a definition has been defined');
    }

    public function testNonSharedServicesReturnsDifferentInstances()
    {
        $builder = new ContainerBuilder();
        $builder->register('bar', 'stdClass')->setShared(false);

        $this->assertNotSame($builder->get('bar'), $builder->get('bar'));
    }

    /**
     * @expectedException        \Symfony\Component\DependencyInjection\Exception\RuntimeException
     * @expectedExceptionMessage You have requested a synthetic service ("foo"). The DIC does not know how to construct this service.
     */
    public function testGetUnsetLoadingServiceWhenCreateServiceThrowsAnException()
    {
        $builder = new ContainerBuilder();
        $builder->register('foo', 'stdClass')->setSynthetic(true);

        // we expect a RuntimeException here as foo is synthetic
        try {
            $builder->get('foo');
        } catch (RuntimeException $e) {
        }

        // we must also have the same RuntimeException here
        $builder->get('foo');
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -196,6 +196,38 @@
     }
 
     /**
+     * @expectedException \Symfony\Component\DependencyInjection\Exception\InvalidArgumentException
+     * @dataProvider provideBadId
+     */
+    public function testBadAliasId($id)
+    {
+        $builder = new ContainerBuilder();
+        $builder->setAlias($id, 'foo');
+    }
+
+    /**
+     * @expectedException \Symfony\Component\DependencyInjection\Exception\InvalidArgumentException
+     * @dataProvider provideBadId
+     */
+    public function testBadDefinitionId($id)
+    {
+        $builder = new ContainerBuilder();
+        $builder->setDefinition($id, new Definition('Foo'));
+    }
+
+    public function provideBadId()
+    {
+        return [
+            [''],
+            ["\0"],
+            ["\r"],
+            ["\n"],
+            ["'"],
+            ['ab\\'],
+        ];
+    }
+
+    /**
      * @expectedException        \Symfony\Component\DependencyInjection\Exception\RuntimeException
      * @expectedExceptionMessage You have requested a synthetic service ("foo"). The DIC does not know how to construct this service.
      */
```
