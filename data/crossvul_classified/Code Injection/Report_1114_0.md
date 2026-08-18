# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 1114_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1114_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 82-122 of the vulnerable file.

                return false;
            }

            return setcookie($keyword, $v, $item->getExpirationDate()->getTimestamp(), '/');
        } else {
            throw new \InvalidArgumentException('Cross-Driver type confusion detected');
        }
    }

    /**
     * @param \Psr\Cache\CacheItemInterface $item
     * @return mixed
     * @throws \phpFastCache\Exceptions\phpFastCacheDriverException
     */
    protected function driverRead(CacheItemInterface $item)
    {
        $this->driverConnect();
        // return null if no caching
        // return value if in caching
        $keyword = self::PREFIX . $item->getKey();
        $x = isset($_COOKIE[ $keyword ]) ? $this->decode(json_decode($_COOKIE[ $keyword ], true)) : false;

        if ($x == false) {
            return null;
        } else {
            if (!is_scalar($this->driverUnwrapData($x)) && !is_null($this->driverUnwrapData($x))) {
                throw new phpFastCacheDriverException('Hacking attempt: The decoding returned a non-scalar value, Cookie driver does not allow this.');
            }

            return $x;
        }
    }

    /**
     * @param $key
     * @return int
     */
    protected function driverReadExpirationDate($key)
    {
        $this->driverConnect();
        $keyword = self::PREFIX . $key;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,7 @@
         // return null if no caching
         // return value if in caching
         $keyword = self::PREFIX . $item->getKey();
-        $x = isset($_COOKIE[ $keyword ]) ? $this->decode(json_decode($_COOKIE[ $keyword ], true)) : false;
+        $x = isset($_COOKIE[ $keyword ]) ? json_decode($_COOKIE[ $keyword ], true) : false;
 
         if ($x == false) {
             return null;
```
