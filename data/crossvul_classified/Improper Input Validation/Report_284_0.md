# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 284_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `284_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1927-1967 of the vulnerable file.


    private function isFromTrustedProxy()
    {
        return self::$trustedProxies && IpUtils::checkIp($this->server->get('REMOTE_ADDR'), self::$trustedProxies);
    }

    private function getTrustedValues($type, $ip = null)
    {
        $clientValues = array();
        $forwardedValues = array();

        if (self::$trustedHeaders[$type] && $this->headers->has(self::$trustedHeaders[$type])) {
            foreach (explode(',', $this->headers->get(self::$trustedHeaders[$type])) as $v) {
                $clientValues[] = (self::HEADER_CLIENT_PORT === $type ? '0.0.0.0:' : '').trim($v);
            }
        }

        if (self::$trustedHeaders[self::HEADER_FORWARDED] && $this->headers->has(self::$trustedHeaders[self::HEADER_FORWARDED])) {
            $forwardedValues = $this->headers->get(self::$trustedHeaders[self::HEADER_FORWARDED]);
            $forwardedValues = preg_match_all(sprintf('{(?:%s)=(?:"?\[?)([a-zA-Z0-9\.:_\-/]*+)}', self::$forwardedParams[$type]), $forwardedValues, $matches) ? $matches[1] : array();
        }

        if (null !== $ip) {
            $clientValues = $this->normalizeAndFilterClientIps($clientValues, $ip);
            $forwardedValues = $this->normalizeAndFilterClientIps($forwardedValues, $ip);
        }

        if ($forwardedValues === $clientValues || !$clientValues) {
            return $forwardedValues;
        }

        if (!$forwardedValues) {
            return $clientValues;
        }

        if (!$this->isForwardedValid) {
            return null !== $ip ? array('0.0.0.0', $ip) : array();
        }
        $this->isForwardedValid = false;

        throw new ConflictingHeadersException(sprintf('The request has both a trusted "%s" header and a trusted "%s" header, conflicting with each other. You should either configure your proxy to remove one of them, or configure your project to distrust the offending one.', self::$trustedHeaders[self::HEADER_FORWARDED], self::$trustedHeaders[$type]));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1944,6 +1944,11 @@
         if (self::$trustedHeaders[self::HEADER_FORWARDED] && $this->headers->has(self::$trustedHeaders[self::HEADER_FORWARDED])) {
             $forwardedValues = $this->headers->get(self::$trustedHeaders[self::HEADER_FORWARDED]);
             $forwardedValues = preg_match_all(sprintf('{(?:%s)=(?:"?\[?)([a-zA-Z0-9\.:_\-/]*+)}', self::$forwardedParams[$type]), $forwardedValues, $matches) ? $matches[1] : array();
+            if (self::HEADER_CLIENT_PORT === $type) {
+                foreach ($forwardedValues as $k => $v) {
+                    $forwardedValues[$k] = substr_replace($v, '0.0.0.0', 0, strrpos($v, ':'));
+                }
+            }
         }
 
         if (null !== $ip) {
```
