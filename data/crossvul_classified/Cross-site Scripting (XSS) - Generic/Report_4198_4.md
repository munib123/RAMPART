# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4198_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4198_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 51-71 of the vulnerable file.


    public function testObjectToSting(): void
    {
        $input = Input::make('name')
            ->title('What is your name?');

        $this->assertStringContainsString('What is your name?', (string) $input);
    }

    public function testDataAttributes(): void
    {
        $input = (string) Input::make('name')
            ->set('data-name', 'Alexandr Chernyaev')
            ->set('data-location', 'Russia')
            ->set('data-hello', 'world!');

        $this->assertStringContainsString('data-name="Alexandr Chernyaev"', $input);
        $this->assertStringContainsString('data-location="Russia"', $input);
        $this->assertStringContainsString('data-hello="world!"', $input);
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,4 +68,18 @@
         $this->assertStringContainsString('data-location="Russia"', $input);
         $this->assertStringContainsString('data-hello="world!"', $input);
     }
+
+    public function testEscapeAttributes(): void
+    {
+        $input = (string) Input::make('name')->value('valueQuote"');
+
+        $this->assertStringContainsString('value="valueQuote&quot;"', $input);
+    }
+
+    public function testRemoveBooleanAttributes(): void
+    {
+        $input = (string) Input::make('name')->required(false);
+
+        $this->assertStringNotContainsString('required', $input);
+    }
 }
```
