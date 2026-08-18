# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 791_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `791_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 217-257 of the vulnerable file.

        $dump = print_r($dumper->dump(['as_files' => true, 'file' => __DIR__, 'hot_path_tag' => 'hot']), true);
        if ('\\' === \DIRECTORY_SEPARATOR) {
            $dump = str_replace('\\\\Fixtures\\\\includes\\\\foo.php', '/Fixtures/includes/foo.php', $dump);
        }
        $this->assertStringMatchesFormatFile(self::$fixturesPath.'/php/services9_as_files.txt', $dump);
    }

    public function testServicesWithAnonymousFactories()
    {
        $container = include self::$fixturesPath.'/containers/container19.php';
        $container->compile();
        $dumper = new PhpDumper($container);

        $this->assertStringEqualsFile(self::$fixturesPath.'/php/services19.php', $dumper->dump(), '->dump() dumps services with anonymous factories');
    }

    public function testAddServiceIdWithUnsupportedCharacters()
    {
        $class = 'Symfony_DI_PhpDumper_Test_Unsupported_Characters';
        $container = new ContainerBuilder();
        $container->register('bar$', 'FooClass')->setPublic(true);
        $container->register('bar$!', 'FooClass')->setPublic(true);
        $container->compile();
        $dumper = new PhpDumper($container);
        eval('?>'.$dumper->dump(['class' => $class]));

        $this->assertTrue(method_exists($class, 'getBarService'));
        $this->assertTrue(method_exists($class, 'getBar2Service'));
    }

    public function testConflictingServiceIds()
    {
        $class = 'Symfony_DI_PhpDumper_Test_Conflicting_Service_Ids';
        $container = new ContainerBuilder();
        $container->register('foo_bar', 'FooClass')->setPublic(true);
        $container->register('foobar', 'FooClass')->setPublic(true);
        $container->compile();
        $dumper = new PhpDumper($container);
        eval('?>'.$dumper->dump(['class' => $class]));

        $this->assertTrue(method_exists($class, 'getFooBarService'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -234,12 +234,18 @@
     {
         $class = 'Symfony_DI_PhpDumper_Test_Unsupported_Characters';
         $container = new ContainerBuilder();
+        $container->setParameter("'", 'oh-no');
+        $container->register("foo*/oh-no", 'FooClass')->setPublic(true);
         $container->register('bar$', 'FooClass')->setPublic(true);
         $container->register('bar$!', 'FooClass')->setPublic(true);
         $container->compile();
         $dumper = new PhpDumper($container);
-        eval('?>'.$dumper->dump(['class' => $class]));
-
+
+        $this->assertStringEqualsFile(self::$fixturesPath.'/php/services_unsupported_characters.php', $dumper->dump(['class' => $class]));
+
+        require_once self::$fixturesPath.'/php/services_unsupported_characters.php';
+
+        $this->assertTrue(method_exists($class, 'getFooOhNoService'));
         $this->assertTrue(method_exists($class, 'getBarService'));
         $this->assertTrue(method_exists($class, 'getBar2Service'));
     }
```
