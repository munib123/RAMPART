# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2805_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2805_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.


if ($user->perm->checkRight($user->getUserId(), 'editconfig')) {
    // actions defined by url: user_action=
    $userAction = PMF_Filter::filterInput(INPUT_GET, 'config_action', FILTER_SANITIZE_STRING, 'listConfig');
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
        $escapeValues = ['main.contactInformations', 'main.customPdfHeader', 'main.customPdfFooter'];

        // Special checks
        if (isset($editData['edit']['main.enableMarkdownEditor'])) {
            $editData['edit']['main.enableWysiwygEditor'] = false; // Disable WYSIWG editor if Markdown is enabled
        }

        foreach ($editData['edit'] as $key => $value) {
            // Remove forbidden characters
            $newConfigValues[$key] = str_replace($forbiddenValues, '', $value);
            // Escape some values
            if (isset($escapeValues[$key])) {
                $newConfigValues[$key] = PMF_String::htmlspecialchars($value, ENT_HTML5);
            }
            $keyArray = array_values(explode('.', $key));
            $newConfigClass = array_shift($keyArray);
        }

        foreach ($oldConfigValues as $key => $value) {
            $keyArray = array_values(explode('.', $key));
            $oldConfigClass = array_shift($keyArray);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,12 @@
         // Set the new values
         $forbiddenValues = ['{', '}', '$'];
         $newConfigValues = [];
-        $escapeValues = ['main.contactInformations', 'main.customPdfHeader', 'main.customPdfFooter'];
+        $escapeValues = [
+            'main.contactInformations',
+            'main.customPdfHeader',
+            'main.customPdfFooter',
+            'main.titleFAQ'
+        ];
 
         // Special checks
         if (isset($editData['edit']['main.enableMarkdownEditor'])) {
@@ -58,7 +63,7 @@
             $newConfigValues[$key] = str_replace($forbiddenValues, '', $value);
             // Escape some values
             if (isset($escapeValues[$key])) {
-                $newConfigValues[$key] = PMF_String::htmlspecialchars($value, ENT_HTML5);
+                $newConfigValues[$key] = PMF_String::htmlspecialchars($value, ENT_QUOTES);
             }
             $keyArray = array_values(explode('.', $key));
             $newConfigClass = array_shift($keyArray);
```
