# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4481_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4481_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 412-452 of the vulnerable file.

                $r = (boolean) @\preg_match(isset($b[0]) && $b[0]=='/' ? $b : '/'.$b.'/iu', $a, $match);
                if ($func === '$not') {
                    $r = !$r;
                }
                break;

            case '$size' :
                if (!\is_array($a)) $a = @\json_decode($a, true) ?  : [];
                $r = (int) $b == \count($a);
                break;

            case '$mod' :
                if (! \is_array($b))
                    throw new \InvalidArgumentException('Invalid argument for $mod option must be array');
                $r = $a % $b[0] == $b[1] ?? 0;
                break;

            case '$func' :
            case '$fn' :
            case '$f' :
                if (! \is_callable($b))
                    throw new \InvalidArgumentException('Function should be callable');
                $r = $b($a);
                break;

            case '$exists':
                $r = $b ? !\is_null($a) : \is_null($a);
                break;

            case '$fuzzy':
            case '$text':

                $distance = 3;
                $minScore = 0.7;

                if (\is_array($b) && isset($b['$search'])) {

                    if (isset($b['$minScore']) && \is_numeric($b['$minScore'])) $minScore = $b['$minScore'];
                    if (isset($b['$distance']) && \is_numeric($b['$distance'])) $distance = $b['$distance'];

                    $b = $b['search'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -429,7 +429,7 @@
             case '$func' :
             case '$fn' :
             case '$f' :
-                if (! \is_callable($b))
+                if (\is_string($b) || !\is_callable($b))
                     throw new \InvalidArgumentException('Function should be callable');
                 $r = $b($a);
                 break;
```
