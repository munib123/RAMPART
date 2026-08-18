# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4573_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4573_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 58-99 of the vulnerable file.

     * @param RequestStack|null $requestStack
     */
    public function __construct(
        RoutingExtension $routingExtension,
        BackUrlProvider $backUrlProvider,
        $requestStack
    ) {
        $this->routingExtension = $routingExtension;
        $this->backUrlProvider = $backUrlProvider;
        $this->requestStack = $requestStack;
    }

    /**
     * {@inheritdoc}
     */
    public function getFunctions()
    {
        return [
            new TwigFunction(
                'pathWithBackUrl',
                [$this, 'getPathWithBackUrl'],
                ['is_safe_callback' => [$this->routingExtension, 'isUrlGenerationSafe']]
            ),
        ];
    }

    /**
     * Gets original path or back url path.
     *
     * @param string $name - route name
     * @param array $parameters - route parameters
     * @param bool $relative
     *
     * @return string
     */
    public function getPathWithBackUrl($name, $parameters = [], $relative = false)
    {
        $fallbackPath = $this->routingExtension->getPath($name, $parameters, $relative);

        if (null === $this->requestStack) {
            return $fallbackPath;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,8 +75,7 @@
         return [
             new TwigFunction(
                 'pathWithBackUrl',
-                [$this, 'getPathWithBackUrl'],
-                ['is_safe_callback' => [$this->routingExtension, 'isUrlGenerationSafe']]
+                [$this, 'getPathWithBackUrl']
             ),
         ];
     }
```
