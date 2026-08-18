# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4570_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4570_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1191-1231 of the vulnerable file.

    {
        $this->context->smarty->assign($params);

        return $this->display(__FILE__, $template);
    }

    /**
     * Check if link rewrite are availables and corrects
     *
     * @param array $params
     */
    public function checkLinksRewrite($params)
    {
        foreach (Language::getLanguages(false) as $language) {
            $idLang = $language['id_lang'];
            $urlNameLang = Tools::getValue('url_name_' . $idLang);
            if ($urlNameLang && Tools::link_rewrite($urlNameLang) != strtolower($urlNameLang)) {
                $params['errors'][] = Tools::displayError(
                    $this->trans(
                        '"%s" is not a valid url',
                        [$urlNameLang],
                        'Modules.Facetedsearch.Admin'
                    )
                );
            }
        }
    }

    /**
     * Dispatch hooks
     *
     * @param string $methodName
     * @param array $arguments
     */
    public function __call($methodName, array $arguments)
    {
        return $this->getHookDispatcher()->dispatch(
            $methodName,
            !empty($arguments[0]) ? $arguments[0] : []
        );
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1208,7 +1208,7 @@
                 $params['errors'][] = Tools::displayError(
                     $this->trans(
                         '"%s" is not a valid url',
-                        [$urlNameLang],
+                        [Tools::safeOutput($urlNameLang, true)],
                         'Modules.Facetedsearch.Admin'
                     )
                 );
```
