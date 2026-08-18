# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4198_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4198_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 228-268 of the vulnerable file.

            });

        return $this;
    }

    /**
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * @return ComponentAttributeBag
     */
    protected function getAllowAttributes(): ComponentAttributeBag
    {
        $allow = array_merge($this->universalAttributes, $this->inlineAttributes);

        $attribute = new ComponentAttributeBag($this->getAttributes());

        return $attribute->filter(function ($value, $attribute) use ($allow) {
            return Str::is($allow, $attribute);
        });
    }

    /**
     * @return ComponentAttributeBag
     */
    protected function getAllowDataAttributes(): ComponentAttributeBag
    {
        return $this->getAllowAttributes()->filter(function (/* @noinspection PhpUnusedParameterInspection */ $value, $key) {
            return Str::startsWith($key, 'data-');
        });
    }

    /**
     * @return string
     */
    protected function getId(): ?string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -245,11 +245,13 @@
     {
         $allow = array_merge($this->universalAttributes, $this->inlineAttributes);
 
-        $attribute = new ComponentAttributeBag($this->getAttributes());
-
-        return $attribute->filter(function ($value, $attribute) use ($allow) {
-            return Str::is($allow, $attribute);
-        });
+        $attributes = collect($this->getAttributes())
+            ->filter(function ($value, $attribute) use ($allow) {
+                return Str::is($allow, $attribute);
+            })->toArray();
+
+        return (new ComponentAttributeBag())
+            ->merge($attributes);
     }
 
     /**
```
