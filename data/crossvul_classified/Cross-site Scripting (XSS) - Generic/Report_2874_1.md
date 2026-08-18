# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2874_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2874_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 467-508 of the vulnerable file.

$keywordsArray = array_merge(explode(',', $keywords), explode(',', $faqConfig->get('main.metaKeywords')));
$keywordsArray = array_filter($keywordsArray, 'strlen');
shuffle($keywordsArray);
$keywords = implode(',', $keywordsArray);

if (!is_null($error)) {
    $loginMessage = '<p class="error">'.$error.'</p>';
} else {
    $loginMessage = '';
}

$faqSeo = new PMF_Seo($faqConfig);

$tplMainPage = array(
    'msgLoginUser' => $user->isLoggedIn() ? $user->getUserData('display_name') : $PMF_LANG['msgLoginUser'],
    'title' => PMF_String::htmlspecialchars($faqConfig->get('main.titleFAQ').$title),
    'baseHref' => $faqSystem->getSystemUri($faqConfig),
    'version' => $faqConfig->get('main.currentVersion'),
    'header' => PMF_String::htmlspecialchars(str_replace('"', '', $faqConfig->get('main.titleFAQ'))),
    'metaTitle' => PMF_String::htmlspecialchars(str_replace('"', '', $faqConfig->get('main.titleFAQ').$title)),
    'metaDescription' => $metaDescription,
    'metaKeywords' => $keywords,
    'metaPublisher' => $faqConfig->get('main.metaPublisher'),
    'metaLanguage' => $PMF_LANG['metaLanguage'],
    'metaCharset' => 'utf-8', // backwards compability
    'metaRobots' => $faqSeo->getMetaRobots($action),
    'phpmyfaqversion' => $faqConfig->get('main.currentVersion'),
    'stylesheet' => $PMF_LANG['dir'] == 'rtl' ? 'style.rtl' : 'style',
    'currentPageUrl' => $currentPageUrl,
    'action' => $action,
    'dir' => $PMF_LANG['dir'],
    'writeSendAdress' => '?'.$sids.'action=search',
    'searchBox' => $PMF_LANG['msgSearch'],
    'categoryId' => ($cat === 0) ? '%' : (int) $cat,
    'showInstantResponse' => '', // @deprecated
    'headerCategories' => $PMF_LANG['msgFullCategories'],
    'msgCategory' => $PMF_LANG['msgCategory'],
    'showCategories' => $categoryHelper->renderNavigation($cat),
    'topCategories' => $categoryHelper->renderMainCategories(),
    'msgExportAllFaqs' => $PMF_LANG['msgExportAllFaqs'],
    'languageBox' => $PMF_LANG['msgLanguageSubmit'],
    'writeLangAdress' => $writeLangAdress,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -484,8 +484,8 @@
     'version' => $faqConfig->get('main.currentVersion'),
     'header' => PMF_String::htmlspecialchars(str_replace('"', '', $faqConfig->get('main.titleFAQ'))),
     'metaTitle' => PMF_String::htmlspecialchars(str_replace('"', '', $faqConfig->get('main.titleFAQ').$title)),
-    'metaDescription' => $metaDescription,
-    'metaKeywords' => $keywords,
+    'metaDescription' => PMF_String::htmlspecialchars($metaDescription),
+    'metaKeywords' => PMF_String::htmlspecialchars($keywords),
     'metaPublisher' => $faqConfig->get('main.metaPublisher'),
     'metaLanguage' => $PMF_LANG['metaLanguage'],
     'metaCharset' => 'utf-8', // backwards compability
```
