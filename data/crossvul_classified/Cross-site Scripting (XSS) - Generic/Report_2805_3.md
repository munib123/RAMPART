# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2805_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2805_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 60-82 of the vulnerable file.

        'writeNewsHeader' => $writeNewsHeader,
        'writeNewsRSS' => $writeNewsRSS,
        'writeNews' => $news->getNews($archived),
        'showAllNews' => $showAllNews,
        'writeNumberOfArticles' => $plr->getMsg('plmsgHomeArticlesOnline', $faq->getNumberOfRecords($LANGCODE)),
        'writeSendAdress' => '?'.$sids.'action=search',
        'searchBox' => $PMF_LANG['msgSearch'],
        'categoryId' => ($cat === 0) ? '%' : (int) $cat,
        'msgSearch' => sprintf(
            '<a class="help" href="%sindex.php?action=search">%s</a>',
            $faqSystem->getSystemUri($faqConfig),
            $PMF_LANG['msgAdvancedSearch']
        )
    ]
);

$tpl->parseBlock(
    'index',
    'breadcrumb',
    [
        'breadcrumbHeadline' => $faqConfig->get('main.titleFAQ')
    ]
);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,6 +77,6 @@
     'index',
     'breadcrumb',
     [
-        'breadcrumbHeadline' => $faqConfig->get('main.titleFAQ')
+        'breadcrumbHeadline' => PMF_String::htmlspecialchars($faqConfig->get('main.titleFAQ'))
     ]
 );
```
