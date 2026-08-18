# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 793_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `793_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 47-87 of the vulnerable file.

        throw new Danger();
    }

    public function registerBundles()
    {
        return [
            new FrameworkBundle(),
        ];
    }

    public function getCacheDir()
    {
        return $this->cacheDir = sys_get_temp_dir().'/sf_micro_kernel';
    }

    public function getLogDir()
    {
        return $this->cacheDir;
    }

    public function __destruct()
    {
        $fs = new Filesystem();
        $fs->remove($this->cacheDir);
    }

    protected function configureRoutes(RouteCollectionBuilder $routes)
    {
        $routes->add('/', 'kernel:halloweenAction');
        $routes->add('/danger', 'kernel:dangerousAction');
    }

    protected function configureContainer(ContainerBuilder $c, LoaderInterface $loader)
    {
        $c->register('logger', NullLogger::class);
        $c->loadFromExtension('framework', [
            'secret' => '$ecret',
        ]);

        $c->setParameter('halloween', 'Have a great day!');
        $c->register('halloween', 'stdClass')->setPublic(true);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,6 +64,16 @@
         return $this->cacheDir;
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
         $fs = new Filesystem();
```
