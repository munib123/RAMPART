# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in php
**Pair ID:** 27_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `27_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```php
Lines 45-85 of the vulnerable file.

     * @throws \LightSaml\Error\LightSamlSecurityException If validation fails
     *
     * @return CredentialInterface|null Returns credential that validated the signature or null if validation was not performed
     */
    public function validateMulti(array $credentialCandidates)
    {
        $lastException = null;

        foreach ($credentialCandidates as $credential) {
            if (false == $credential instanceof CredentialInterface) {
                throw new \InvalidArgumentException('Expected CredentialInterface');
            }
            if (null == $credential->getPublicKey()) {
                continue;
            }

            try {
                $result = $this->validate($credential->getPublicKey());

                if ($result === false) {
                    return;
                }

                return $credential;
            } catch (LightSamlSecurityException $ex) {
                $lastException = $ex;
            }
        }

        if ($lastException) {
            throw $lastException;
        } else {
            throw new LightSamlSecurityException('No public key available for signature verification');
        }
    }

    /**
     * @return string
     */
    abstract public function getAlgorithm();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,7 +62,7 @@
                 $result = $this->validate($credential->getPublicKey());
 
                 if ($result === false) {
-                    return;
+                    return null;
                 }
 
                 return $credential;
@@ -91,6 +91,16 @@
     protected function castKeyIfNecessary(XMLSecurityKey $key)
     {
         $algorithm = $this->getAlgorithm();
+
+        if (!in_array($algorithm, [
+            XMLSecurityKey::RSA_SHA1,
+            XMLSecurityKey::RSA_SHA256,
+            XMLSecurityKey::RSA_SHA384,
+            XMLSecurityKey::RSA_SHA512,
+        ])) {
+            throw new LightSamlSecurityException(sprintf('Unsupported signing algorithm: "%s"', $algorithm));
+        }
+
         if ($algorithm != $key->type) {
             $key = KeyHelper::castKey($key, $algorithm);
         }
```
