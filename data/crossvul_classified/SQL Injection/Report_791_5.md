# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 791_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `791_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 49-81 of the vulnerable file.


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
     * Gets the public 'Bar\Foo' shared service.
     *
     * @return \Bar\Foo
     */
    protected function getFooService()
    {
        return $this->services['Bar\Foo'] = new \Bar\Foo();
    }

    /**
     * Gets the public 'Foo\Foo' shared service.
     *
     * @return \Foo\Foo
     */
    protected function getFoo2Service()
    {
        return $this->services['Foo\Foo'] = new \Foo\Foo();
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -66,7 +66,7 @@
      */
     protected function getFooService()
     {
-        return $this->services['Bar\Foo'] = new \Bar\Foo();
+        return $this->services['Bar\\Foo'] = new \Bar\Foo();
     }
 
     /**
@@ -76,6 +76,6 @@
      */
     protected function getFoo2Service()
     {
-        return $this->services['Foo\Foo'] = new \Foo\Foo();
+        return $this->services['Foo\\Foo'] = new \Foo\Foo();
     }
 }
```
