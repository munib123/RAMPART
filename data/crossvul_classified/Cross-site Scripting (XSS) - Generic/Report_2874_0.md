# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2874_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2874_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 33-73 of the vulnerable file.

    $csrfToken = PMF_Filter::filterInput(INPUT_POST, 'csrf', FILTER_SANITIZE_STRING);
    $currentToken = $user->getCsrfTokenFromSession();

    // Save the configuration
    if ('saveConfig' === $userAction && $currentToken === $csrfToken) {
        $checks = array(
            'filter' => FILTER_UNSAFE_RAW,
            'flags' => FILTER_REQUIRE_ARRAY,
        );
        $editData = PMF_Filter::filterInputArray(INPUT_POST, array('edit' => $checks));
        $userAction = 'listConfig';
        $oldConfigValues = $faqConfig->config;

        // Set the new values
        $forbiddenValues = ['{', '}', '$'];
        $newConfigValues = [];
        $escapeValues = [
            'main.contactInformations',
            'main.customPdfHeader',
            'main.customPdfFooter',
            'main.titleFAQ'
        ];

        // Special checks
        if (isset($editData['edit']['main.enableMarkdownEditor'])) {
            $editData['edit']['main.enableWysiwygEditor'] = false; // Disable WYSIWG editor if Markdown is enabled
        }

        foreach ($editData['edit'] as $key => $value) {
            // Remove forbidden characters
            $newConfigValues[$key] = str_replace($forbiddenValues, '', $value);
            // Escape some values
            if (isset($escapeValues[$key])) {
                $newConfigValues[$key] = PMF_String::htmlspecialchars($value, ENT_QUOTES);
            }
            $keyArray = array_values(explode('.', $key));
            $newConfigClass = array_shift($keyArray);
        }

        foreach ($oldConfigValues as $key => $value) {
            $keyArray = array_values(explode('.', $key));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,7 +50,8 @@
             'main.contactInformations',
             'main.customPdfHeader',
             'main.customPdfFooter',
-            'main.titleFAQ'
+            'main.titleFAQ',
+            'main.metaKeywords'
         ];
 
         // Special checks
```
