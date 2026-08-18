# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4133_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4133_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 545-585 of the vulnerable file.

      $it = $this->it->execute('foo', ['bar' => 1]);
      $this->string($it->getSql())->isIdenticalTo('SELECT * FROM `foo` WHERE `bar` = \'1\'');

      $this->exception(
         function() {
            $it = $this->it->execute('foo', ['bar' => []]);
         }
      )
         ->isInstanceOf('RuntimeException')
         ->hasMessage('Empty IN are not allowed');

      $it = $this->it->execute('foo', ['bar' => [1, 2, 4]]);
      $this->string($it->getSql())->isIdenticalTo("SELECT * FROM `foo` WHERE `bar` IN ('1', '2', '4')");

      $it = $this->it->execute('foo', ['bar' => ['a', 'b', 'c']]);
      $this->string($it->getSql())->isIdenticalTo("SELECT * FROM `foo` WHERE `bar` IN ('a', 'b', 'c')");

      $it = $this->it->execute('foo', ['bar' => 'val']);
      $this->string($it->getSql())->isIdenticalTo("SELECT * FROM `foo` WHERE `bar` = 'val'");

      $it = $this->it->execute('foo', ['bar' => '`field`']);
      $this->string($it->getSql())->isIdenticalTo('SELECT * FROM `foo` WHERE `bar` = `field`');

      $it = $this->it->execute('foo', ['bar' => '?']);
      $this->string($it->getSql())->isIdenticalTo('SELECT * FROM `foo` WHERE `bar` = \'?\'');

      $it = $this->it->execute('foo', ['bar' => new \QueryParam()]);
      $this->string($it->getSql())->isIdenticalTo('SELECT * FROM `foo` WHERE `bar` = ?');

      $it = $this->it->execute('foo', ['bar' => new \QueryParam('myparam')]);
      $this->string($it->getSql())->isIdenticalTo('SELECT * FROM `foo` WHERE `bar` = :myparam');
   }


   public function testFkey() {

      $it = $this->it->execute(['foo', 'bar'], ['FKEY' => ['id', 'fk']]);
      $this->string($it->getSql())->isIdenticalTo('SELECT * FROM `foo`, `bar` WHERE `id` = `fk`');

      $it = $this->it->execute(['foo', 'bar'], ['FKEY' => ['foo' => 'id', 'bar' => 'fk']]);
      $this->string($it->getSql())->isIdenticalTo('SELECT * FROM `foo`, `bar` WHERE `foo`.`id` = `bar`.`fk`');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -562,7 +562,7 @@
       $it = $this->it->execute('foo', ['bar' => 'val']);
       $this->string($it->getSql())->isIdenticalTo("SELECT * FROM `foo` WHERE `bar` = 'val'");
 
-      $it = $this->it->execute('foo', ['bar' => '`field`']);
+      $it = $this->it->execute('foo', ['bar' => new \QueryExpression('`field`')]);
       $this->string($it->getSql())->isIdenticalTo('SELECT * FROM `foo` WHERE `bar` = `field`');
 
       $it = $this->it->execute('foo', ['bar' => '?']);
```
