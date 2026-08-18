# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 791_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `791_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 41-81 of the vulnerable file.

        $this->proxyGenerator = new LazyLoadingValueHolderGenerator();
        $this->classGenerator = new BaseGeneratorStrategy();
    }

    /**
     * {@inheritdoc}
     */
    public function isProxyCandidate(Definition $definition)
    {
        return $definition->isLazy() && ($class = $definition->getClass()) && class_exists($class);
    }

    /**
     * {@inheritdoc}
     */
    public function getProxyFactoryCode(Definition $definition, $id, $factoryCode = null)
    {
        $instantiation = 'return';

        if ($definition->isShared()) {
            $instantiation .= sprintf(' $this->%s[\'%s\'] =', \method_exists(ContainerBuilder::class, 'addClassResource') || ($definition->isPublic() && !$definition->isPrivate()) ? 'services' : 'privates', $id);
        }

        if (null === $factoryCode) {
            @trigger_error(sprintf('The "%s()" method expects a third argument defining the code to execute to construct your service since Symfony 3.4, providing it will be required in 4.0.', __METHOD__), E_USER_DEPRECATED);
            $factoryCode = '$this->get'.Container::camelize($id).'Service(false)';
        } elseif (false === strpos($factoryCode, '(')) {
            @trigger_error(sprintf('The "%s()" method expects its third argument to define the code to execute to construct your service since Symfony 3.4, providing it will be required in 4.0.', __METHOD__), E_USER_DEPRECATED);
            $factoryCode = "\$this->$factoryCode(false)";
        }
        $proxyClass = $this->getProxyClassName($definition);

        $hasStaticConstructor = $this->generateProxyClass($definition)->hasMethod('staticProxyConstructor');

        $constructorCall = sprintf($hasStaticConstructor ? '%s::staticProxyConstructor' : 'new %s', '\\'.$proxyClass);

        return <<<EOF
        if (\$lazyLoad) {
            $instantiation \$this->createProxy('$proxyClass', function () {
                return $constructorCall(function (&\$wrappedInstance, \ProxyManager\Proxy\LazyLoadingInterface \$proxy) {
                    \$wrappedInstance = $factoryCode;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,7 +58,7 @@
         $instantiation = 'return';
 
         if ($definition->isShared()) {
-            $instantiation .= sprintf(' $this->%s[\'%s\'] =', \method_exists(ContainerBuilder::class, 'addClassResource') || ($definition->isPublic() && !$definition->isPrivate()) ? 'services' : 'privates', $id);
+            $instantiation .= sprintf(' $this->%s[%s] =', \method_exists(ContainerBuilder::class, 'addClassResource') || ($definition->isPublic() && !$definition->isPrivate()) ? 'services' : 'privates', var_export($id, true));
         }
 
         if (null === $factoryCode) {
```
