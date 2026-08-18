# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4333_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4333_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 174-214 of the vulnerable file.

     */
    public function ignoreEmptyAttributes($ignoreEmptyAttributes)
    {
        $this->ignoreEmptyAttributes = $ignoreEmptyAttributes;
        if ($ignoreEmptyAttributes) {
            $this->attributes = array_filter($this->attributes, function ($item) { return trim((string) $item) !== ''; });
        }
    }

    /**
     * Adds an attribute to the $attributes-collection
     *
     * @param string $attributeName name of the attribute to be added to the tag
     * @param string $attributeValue attribute value
     * @param boolean $escapeSpecialCharacters apply htmlspecialchars to attribute value
     * @return void
     * @api
     */
    public function addAttribute($attributeName, $attributeValue, $escapeSpecialCharacters = true)
    {
        if ($attributeName === 'data' && (is_array($attributeValue) || $attributeValue instanceof \Traversable)) {
            foreach ($attributeValue as $name => $value) {
                $this->addAttribute('data-' . $name, $value, $escapeSpecialCharacters);
            }
        } else {
            if (trim((string) $attributeValue) === '' && $this->ignoreEmptyAttributes) {
                return;
            }
            if ($escapeSpecialCharacters) {
                $attributeValue = htmlspecialchars($attributeValue);
            }
            $this->attributes[$attributeName] = $attributeValue;
        }
    }

    /**
     * Adds attributes to the $attributes-collection
     *
     * @param array $attributes collection of attributes to add. key = attribute name, value = attribute value
     * @param boolean $escapeSpecialCharacters apply htmlspecialchars to attribute values#
     * @return void
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -191,6 +191,9 @@
      */
     public function addAttribute($attributeName, $attributeValue, $escapeSpecialCharacters = true)
     {
+        if ($escapeSpecialCharacters) {
+            $attributeName = htmlspecialchars($attributeName);
+        }
         if ($attributeName === 'data' && (is_array($attributeValue) || $attributeValue instanceof \Traversable)) {
             foreach ($attributeValue as $name => $value) {
                 $this->addAttribute('data-' . $name, $value, $escapeSpecialCharacters);
```
