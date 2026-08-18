# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 794_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `794_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1329-1381 of the vulnerable file.

        $this->server->set('REQUEST_METHOD', $method);
    }

    /**
     * Gets the request "intended" method.
     *
     * If the X-HTTP-Method-Override header is set, and if the method is a POST,
     * then it is used to determine the "real" intended HTTP method.
     *
     * The _method request parameter can also be used to determine the HTTP method,
     * but only if enableHttpMethodParameterOverride() has been called.
     *
     * The method is always an uppercased string.
     *
     * @return string The request method
     *
     * @see getRealMethod()
     */
    public function getMethod()
    {
        if (null === $this->method) {
            $this->method = strtoupper($this->server->get('REQUEST_METHOD', 'GET'));

            if ('POST' === $this->method) {
                if ($method = $this->headers->get('X-HTTP-METHOD-OVERRIDE')) {
                    $this->method = strtoupper($method);
                } elseif (self::$httpMethodParameterOverride) {
                    $method = $this->request->get('_method', $this->query->get('_method', 'POST'));
                    if (\is_string($method)) {
                        $this->method = strtoupper($method);
                    }
                }
            }
        }

        return $this->method;
    }

    /**
     * Gets the "real" request method.
     *
     * @return string The request method
     *
     * @see getMethod()
     */
    public function getRealMethod()
    {
        return strtoupper($this->server->get('REQUEST_METHOD', 'GET'));
    }

    /**
     * Gets the mime type associated with the format.
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1346,22 +1346,37 @@
      */
     public function getMethod()
     {
-        if (null === $this->method) {
-            $this->method = strtoupper($this->server->get('REQUEST_METHOD', 'GET'));
-
-            if ('POST' === $this->method) {
-                if ($method = $this->headers->get('X-HTTP-METHOD-OVERRIDE')) {
-                    $this->method = strtoupper($method);
-                } elseif (self::$httpMethodParameterOverride) {
-                    $method = $this->request->get('_method', $this->query->get('_method', 'POST'));
-                    if (\is_string($method)) {
-                        $this->method = strtoupper($method);
-                    }
-                }
-            }
-        }
-
-        return $this->method;
+        if (null !== $this->method) {
+            return $this->method;
+        }
+
+        $this->method = strtoupper($this->server->get('REQUEST_METHOD', 'GET'));
+
+        if ('POST' !== $this->method) {
+            return $this->method;
+        }
+
+        $method = $this->headers->get('X-HTTP-METHOD-OVERRIDE');
+
+        if (!$method && self::$httpMethodParameterOverride) {
+            $method = $this->request->get('_method', $this->query->get('_method', 'POST'));
+        }
+
+        if (!\is_string($method)) {
+            return $this->method;
+        }
+
+        $method = strtoupper($method);
+
+        if (\in_array($method, ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'PATCH', 'PURGE', 'TRACE'], true)) {
+            return $this->method = $method;
+        }
+
+        if (!preg_match('/^[A-Z]++$/D', $method)) {
+            throw new SuspiciousOperationException(sprintf('Invalid method override "%s".', $method));
+        }
+
+        return $this->method = $method;
     }
 
     /**
```
