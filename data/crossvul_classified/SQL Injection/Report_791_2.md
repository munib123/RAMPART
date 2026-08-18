# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 791_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `791_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 466-506 of the vulnerable file.

     * @param Definition $definition
     * @param bool       $isSimpleInstance
     *
     * @return string
     *
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    private function addServiceInstance($id, Definition $definition, $isSimpleInstance)
    {
        $class = $this->dumpValue($definition->getClass());

        if (0 === strpos($class, "'") && false === strpos($class, '$') && !preg_match('/^\'(?:\\\{2})?[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*(?:\\\{2}[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)*\'$/', $class)) {
            throw new InvalidArgumentException(sprintf('"%s" is not a valid class name for the "%s" service.', $class, $id));
        }

        $isProxyCandidate = $this->getProxyDumper()->isProxyCandidate($definition);
        $instantiation = '';

        if (!$isProxyCandidate && $definition->isShared()) {
            $instantiation = "\$this->services['$id'] = ".($isSimpleInstance ? '' : '$instance');
        } elseif (!$isSimpleInstance) {
            $instantiation = '$instance';
        }

        $return = '';
        if ($isSimpleInstance) {
            $return = 'return ';
        } else {
            $instantiation .= ' = ';
        }

        return $this->addNewInstance($definition, $return, $instantiation, $id);
    }

    /**
     * Checks if the definition is a trivial instance.
     *
     * @param Definition $definition
     *
     * @return bool
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -483,7 +483,7 @@
         $instantiation = '';
 
         if (!$isProxyCandidate && $definition->isShared()) {
-            $instantiation = "\$this->services['$id'] = ".($isSimpleInstance ? '' : '$instance');
+            $instantiation = sprintf('$this->services[%s] = %s', $this->doExport($id), $isSimpleInstance ? '' : '$instance');
         } elseif (!$isSimpleInstance) {
             $instantiation = '$instance';
         }
@@ -679,6 +679,9 @@
      * Gets the $public '$id'$shared$autowired service.
      *
      * $return
+EOF;
+            $code = str_replace('*/', ' ', $code).<<<EOF
+
      */
     protected function {$methodName}($lazyInitialization)
     {
@@ -693,7 +696,7 @@
 
         if ($this->getProxyDumper()->isProxyCandidate($definition)) {
             $factoryCode = $asFile ? "\$this->load('%s.php', false)" : '$this->%s(false)';
-            $code .= $this->getProxyDumper()->getProxyFactoryCode($definition, $id, sprintf($factoryCode, $methodName));
+            $code .= $this->getProxyDumper()->getProxyFactoryCode($definition, $id, sprintf($factoryCode, $methodName, $this->doExport($id)));
         }
 
         if ($definition->isDeprecated()) {
@@ -767,14 +770,14 @@
 
         $code .= sprintf(<<<'EOTXT'
 
-        if (isset($this->%s['%s'])) {
-            return $this->%1$s['%2$s'];
+        if (isset($this->%s[%s])) {
+            return $this->%1$s[%2$s];
         }
 
 EOTXT
             ,
             'services',
-            $id
+            $this->doExport($id)
         );
 
         return $code;
@@ -1530,14 +1533,14 @@
             if (!$this->container->hasDefinition($service)) {
                 return 'false';
             }
-            $conditions[] = sprintf("isset(\$this->services['%s'])", $service);
+            $conditions[] = sprintf('isset($this->services[%s])', $this->doExport($service));
         }
         foreach (ContainerBuilder::getServiceConditionals($value) as $service) {
             if ($this->container->hasDefinition($service) && !$this->container->getDefinition($service)->isPublic()) {
                 continue;
             }
 
-            $conditions[] = sprintf("\$this->has('%s')", $service);
+            $conditions[] = sprintf('$this->has(%s)', $this->doExport($service));
         }
 
         if (!$conditions) {
@@ -1776,6 +1779,8 @@
      */
     private function dumpParameter($name)
     {
+        $name = (string) $name;
+
         if ($this->container->isCompiled() && $this->container->hasParameter($name)) {
             $value = $this->container->getParameter($name);
             $dumpedValue = $this->dumpValue($value, false);
@@ -1785,11 +1790,11 @@
             }
 
             if (!preg_match("/\\\$this->(?:getEnv\('(?:\w++:)*+\w++'\)|targetDirs\[\d++\])/", $dumpedValue)) {
-                return sprintf("\$this->parameters['%s']", $name);
-            }
-        }
-
-        return sprintf("\$this->getParameter('%s')", $name);
+                return sprintf('$this->parameters[%s]', $this->doExport($name));
+            }
+        }
+
+        return sprintf('$this->getParameter(%s)', $this->doExport($name));
     }
 
     /**
@@ -1813,7 +1818,7 @@
 
         if ($this->container->hasDefinition($id) && $definition = $this->container->getDefinition($id)) {
             if ($definition->isSynthetic()) {
-                $code = sprintf('$this->get(\'%s\'%s)', $id, null !== $reference ? ', '.$reference->getInvalidBehavior() : '');
+                $code = sprintf('$this->get(%s%s)', $this->doExport($id), null !== $reference ? ', '.$reference->getInvalidBehavior() : '');
             } elseif (null !== $reference && ContainerInterface::IGNORE_ON_UNINITIALIZED_REFERENCE === $reference->getInvalidBehavior()) {
                 $code = 'null';
                 if (!$definition->isShared()) {
@@ -1822,7 +1827,7 @@
             } elseif ($this->isTrivialInstance($definition)) {
                 $code = substr($this->addNewInstance($definition, '', '', $id), 8, -2);
                 if ($definition->isShared()) {
-                    $code = sprintf('$this->services[\'%s\'] = %s', $id, $code);
+                    $code = sprintf('$this->services[%s] = %s', $this->doExport($id), $code);
                 }
                 $code = "($code)";
             } elseif ($this->asFiles && $definition->isShared() && !$this->isHotPath($definition)) {
@@ -1833,14 +1838,14 @@
         } elseif (null !== $reference && ContainerInterface::IGNORE_ON_UNINITIALIZED_REFERENCE === $reference->getInvalidBehavior()) {
             return 'null';
         } elseif (null !== $reference && ContainerInterface::EXCEPTION_ON_INVALID_REFERENCE !== $reference->getInvalidBehavior()) {
-            $code = sprintf('$this->get(\'%s\', /* ContainerInterface::NULL_ON_INVALID_REFERENCE */ %d)', $id, ContainerInterface::NULL_ON_INVALID_REFERENCE);
+            $code = sprintf('$this->get(%s, /* ContainerInterface::NULL_ON_INVALID_REFERENCE */ %d)', $this->doExport($id), ContainerInterface::NULL_ON_INVALID_REFERENCE);
         } else {
-            $code = sprintf('$this->get(\'%s\')', $id);
+            $code = sprintf('$this->get(%s)', $this->doExport($id));
         }
 
         // The following is PHP 5.5 syntax for what could be written as "(\$this->services['$id'] ?? $code)" on PHP>=7.0
 
-        return "\${(\$_ = isset(\$this->services['$id']) ? \$this->services['$id'] : $code) && false ?: '_'}";
+        return sprintf("\${(\$_ = isset(\$this->services[%s]) ? \$this->services[%1\$s] : %s) && false ?: '_'}", $this->doExport($id), $code);
     }
 
     /**
```
