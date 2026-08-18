# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 791_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `791_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 71-111 of the vulnerable file.


    public function isCompiled()
    {
        return true;
    }

    public function isFrozen()
    {
        @trigger_error(sprintf('The %s() method is deprecated since Symfony 3.3 and will be removed in 4.0. Use the isCompiled() method instead.', __METHOD__), E_USER_DEPRECATED);

        return true;
    }

    /**
     * Gets the public 'App\Bus' shared service.
     *
     * @return \App\Bus
     */
    protected function getBusService()
    {
        $this->services['App\Bus'] = $instance = new \App\Bus(${($_ = isset($this->services['App\Db']) ? $this->services['App\Db'] : $this->getDbService()) && false ?: '_'});

        $instance->handler1 = ${($_ = isset($this->services['App\Handler1']) ? $this->services['App\Handler1'] : $this->getHandler1Service()) && false ?: '_'};
        $instance->handler2 = ${($_ = isset($this->services['App\Handler2']) ? $this->services['App\Handler2'] : $this->getHandler2Service()) && false ?: '_'};

        return $instance;
    }

    /**
     * Gets the public 'App\Db' shared service.
     *
     * @return \App\Db
     */
    protected function getDbService()
    {
        $this->services['App\Db'] = $instance = new \App\Db();

        $instance->schema = ${($_ = isset($this->services['App\Schema']) ? $this->services['App\Schema'] : $this->getSchemaService()) && false ?: '_'};

        return $instance;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,10 +88,10 @@
      */
     protected function getBusService()
     {
-        $this->services['App\Bus'] = $instance = new \App\Bus(${($_ = isset($this->services['App\Db']) ? $this->services['App\Db'] : $this->getDbService()) && false ?: '_'});
+        $this->services['App\\Bus'] = $instance = new \App\Bus(${($_ = isset($this->services['App\\Db']) ? $this->services['App\\Db'] : $this->getDbService()) && false ?: '_'});
 
-        $instance->handler1 = ${($_ = isset($this->services['App\Handler1']) ? $this->services['App\Handler1'] : $this->getHandler1Service()) && false ?: '_'};
-        $instance->handler2 = ${($_ = isset($this->services['App\Handler2']) ? $this->services['App\Handler2'] : $this->getHandler2Service()) && false ?: '_'};
+        $instance->handler1 = ${($_ = isset($this->services['App\\Handler1']) ? $this->services['App\\Handler1'] : $this->getHandler1Service()) && false ?: '_'};
+        $instance->handler2 = ${($_ = isset($this->services['App\\Handler2']) ? $this->services['App\\Handler2'] : $this->getHandler2Service()) && false ?: '_'};
 
         return $instance;
     }
@@ -103,9 +103,9 @@
      */
     protected function getDbService()
     {
-        $this->services['App\Db'] = $instance = new \App\Db();
+        $this->services['App\\Db'] = $instance = new \App\Db();
 
-        $instance->schema = ${($_ = isset($this->services['App\Schema']) ? $this->services['App\Schema'] : $this->getSchemaService()) && false ?: '_'};
+        $instance->schema = ${($_ = isset($this->services['App\\Schema']) ? $this->services['App\\Schema'] : $this->getSchemaService()) && false ?: '_'};
 
         return $instance;
     }
@@ -117,13 +117,13 @@
      */
     protected function getHandler1Service()
     {
-        $a = ${($_ = isset($this->services['App\Processor']) ? $this->services['App\Processor'] : $this->getProcessorService()) && false ?: '_'};
+        $a = ${($_ = isset($this->services['App\\Processor']) ? $this->services['App\\Processor'] : $this->getProcessorService()) && false ?: '_'};
 
-        if (isset($this->services['App\Handler1'])) {
-            return $this->services['App\Handler1'];
+        if (isset($this->services['App\\Handler1'])) {
+            return $this->services['App\\Handler1'];
         }
 
-        return $this->services['App\Handler1'] = new \App\Handler1(${($_ = isset($this->services['App\Db']) ? $this->services['App\Db'] : $this->getDbService()) && false ?: '_'}, ${($_ = isset($this->services['App\Schema']) ? $this->services['App\Schema'] : $this->getSchemaService()) && false ?: '_'}, $a);
+        return $this->services['App\\Handler1'] = new \App\Handler1(${($_ = isset($this->services['App\\Db']) ? $this->services['App\\Db'] : $this->getDbService()) && false ?: '_'}, ${($_ = isset($this->services['App\\Schema']) ? $this->services['App\\Schema'] : $this->getSchemaService()) && false ?: '_'}, $a);
     }
 
     /**
@@ -133,13 +133,13 @@
      */
     protected function getHandler2Service()
     {
-        $a = ${($_ = isset($this->services['App\Processor']) ? $this->services['App\Processor'] : $this->getProcessorService()) && false ?: '_'};
+        $a = ${($_ = isset($this->services['App\\Processor']) ? $this->services['App\\Processor'] : $this->getProcessorService()) && false ?: '_'};
 
-        if (isset($this->services['App\Handler2'])) {
-            return $this->services['App\Handler2'];
+        if (isset($this->services['App\\Handler2'])) {
+            return $this->services['App\\Handler2'];
         }
 
-        return $this->services['App\Handler2'] = new \App\Handler2(${($_ = isset($this->services['App\Db']) ? $this->services['App\Db'] : $this->getDbService()) && false ?: '_'}, ${($_ = isset($this->services['App\Schema']) ? $this->services['App\Schema'] : $this->getSchemaService()) && false ?: '_'}, $a);
+        return $this->services['App\\Handler2'] = new \App\Handler2(${($_ = isset($this->services['App\\Db']) ? $this->services['App\\Db'] : $this->getDbService()) && false ?: '_'}, ${($_ = isset($this->services['App\\Schema']) ? $this->services['App\\Schema'] : $this->getSchemaService()) && false ?: '_'}, $a);
     }
 
     /**
@@ -149,13 +149,13 @@
      */
     protected function getProcessorService()
     {
-        $a = ${($_ = isset($this->services['App\Registry']) ? $this->services['App\Registry'] : $this->getRegistryService()) && false ?: '_'};
+        $a = ${($_ = isset($this->services['App\\Registry']) ? $this->services['App\\Registry'] : $this->getRegistryService()) && false ?: '_'};
 
-        if (isset($this->services['App\Processor'])) {
-            return $this->services['App\Processor'];
+        if (isset($this->services['App\\Processor'])) {
+            return $this->services['App\\Processor'];
         }
 
-        return $this->services['App\Processor'] = new \App\Processor($a, ${($_ = isset($this->services['App\Db']) ? $this->services['App\Db'] : $this->getDbService()) && false ?: '_'});
+        return $this->services['App\\Processor'] = new \App\Processor($a, ${($_ = isset($this->services['App\\Db']) ? $this->services['App\\Db'] : $this->getDbService()) && false ?: '_'});
     }
 
     /**
@@ -165,9 +165,9 @@
      */
     protected function getRegistryService()
     {
-        $this->services['App\Registry'] = $instance = new \App\Registry();
+        $this->services['App\\Registry'] = $instance = new \App\Registry();
 
-        $instance->processor = [0 => ${($_ = isset($this->services['App\Db']) ? $this->services['App\Db'] : $this->getDbService()) && false ?: '_'}, 1 => ${($_ = isset($this->services['App\Bus']) ? $this->services['App\Bus'] : $this->getBusService()) && false ?: '_'}];
+        $instance->processor = [0 => ${($_ = isset($this->services['App\\Db']) ? $this->services['App\\Db'] : $this->getDbService()) && false ?: '_'}, 1 => ${($_ = isset($this->services['App\\Bus']) ? $this->services['App\\Bus'] : $this->getBusService()) && false ?: '_'}];
 
         return $instance;
     }
@@ -179,12 +179,12 @@
      */
     protected function getSchemaService()
     {
-        $a = ${($_ = isset($this->services['App\Db']) ? $this->services['App\Db'] : $this->getDbService()) && false ?: '_'};
+        $a = ${($_ = isset($this->services['App\\Db']) ? $this->services['App\\Db'] : $this->getDbService()) && false ?: '_'};
 
-        if (isset($this->services['App\Schema'])) {
-            return $this->services['App\Schema'];
+        if (isset($this->services['App\\Schema'])) {
+            return $this->services['App\\Schema'];
         }
 
-        return $this->services['App\Schema'] = new \App\Schema($a);
+        return $this->services['App\\Schema'] = new \App\Schema($a);
     }
 }
```
