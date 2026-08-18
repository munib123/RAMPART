# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2462_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2462_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1573-1613 of the vulnerable file.

     *
     * @return array The entity tags
     */
    public function getETags()
    {
        return preg_split('/\s*,\s*/', $this->headers->get('if_none_match'), null, PREG_SPLIT_NO_EMPTY);
    }

    /**
     * @return bool
     */
    public function isNoCache()
    {
        return $this->headers->hasCacheControlDirective('no-cache') || 'no-cache' == $this->headers->get('Pragma');
    }

    /**
     * Gets the preferred format for the response by inspecting, in the following order:
     *   * the request format set using setRequestFormat
     *   * the values of the Accept HTTP header
     *   * the content type of the body of the request.
     */
    public function getPreferredFormat(?string $default = 'html'): ?string
    {
        if (null !== $this->preferredFormat || null !== $this->preferredFormat = $this->getRequestFormat(null)) {
            return $this->preferredFormat;
        }

        foreach ($this->getAcceptableContentTypes() as $mimeType) {
            if ($this->preferredFormat = $this->getFormat($mimeType)) {
                return $this->preferredFormat;
            }
        }

        return $default;
    }

    /**
     * Returns the preferred language.
     *
     * @param string[] $locales An array of ordered available locales
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1590,7 +1590,9 @@
      * Gets the preferred format for the response by inspecting, in the following order:
      *   * the request format set using setRequestFormat
      *   * the values of the Accept HTTP header
-     *   * the content type of the body of the request.
+     *
+     * Note that if you use this method, you should send the "Vary: Accept" header
+     * in the response to prevent any issues with intermediary HTTP caches.
      */
     public function getPreferredFormat(?string $default = 'html'): ?string
     {
```
