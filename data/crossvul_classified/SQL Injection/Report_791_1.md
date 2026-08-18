# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 791_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `791_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 851-891 of the vulnerable file.

    {
        $this->aliasDefinitions = [];
        $this->addAliases($aliases);
    }

    /**
     * Sets an alias for an existing service.
     *
     * @param string       $alias The alias to create
     * @param string|Alias $id    The service to alias
     *
     * @return Alias
     *
     * @throws InvalidArgumentException if the id is not a string or an Alias
     * @throws InvalidArgumentException if the alias is for itself
     */
    public function setAlias($alias, $id)
    {
        $alias = $this->normalizeId($alias);

        if (\is_string($id)) {
            $id = new Alias($this->normalizeId($id));
        } elseif (!$id instanceof Alias) {
            throw new InvalidArgumentException('$id must be a string, or an Alias object.');
        }

        if ($alias === (string) $id) {
            throw new InvalidArgumentException(sprintf('An alias can not reference itself, got a circular reference on "%s".', $alias));
        }

        unset($this->definitions[$alias], $this->removedIds[$alias]);

        return $this->aliasDefinitions[$alias] = $id;
    }

    /**
     * Removes an alias.
     *
     * @param string $alias The alias to remove
     */
    public function removeAlias($alias)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -868,6 +868,10 @@
     {
         $alias = $this->normalizeId($alias);
 
+        if ('' === $alias || '\\' === substr($alias, -1) || \strlen($alias) !== strcspn($alias, "\0\r\n'")) {
+            throw new InvalidArgumentException(sprintf('Invalid alias id: "%s"', $alias));
+        }
+
         if (\is_string($id)) {
             $id = new Alias($this->normalizeId($id));
         } elseif (!$id instanceof Alias) {
@@ -1020,6 +1024,10 @@
         }
 
         $id = $this->normalizeId($id);
+
+        if ('' === $id || '\\' === substr($id, -1) || \strlen($id) !== strcspn($id, "\0\r\n'")) {
+            throw new InvalidArgumentException(sprintf('Invalid service id: "%s"', $id));
+        }
 
         unset($this->aliasDefinitions[$id], $this->removedIds[$id]);
 
```
