# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in yaml
**Pair ID:** 4565_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4565_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```yaml
Lines 72-102 of the vulnerable file.

        - { name: kernel.event_listener, event: kernel.controller, method: onKernelController }

    prestashop.bundle.event_listener.filter_category_search_criteria:
        class: PrestaShopBundle\EventListener\FilterCategorySearchCriteriaListener
        arguments:
            - '@prestashop.adapter.grid.search.factory.search_criteria_with_category_parent_id'
        tags:
            - { name: kernel.event_listener, event: prestashop.search_criteria.filter, method: onFilterSearchCriteria }

    prestashop.bundle.event_listener.filter_cms_page_category_search_criteria:
        class: PrestaShopBundle\EventListener\FilterCmsPageCategorySearchCriteriaListener
        arguments:
            - '@request_stack'
        tags:
            - { name: kernel.event_listener, event: prestashop.search_criteria.filter, method: onFilterSearchCriteria }

    prestashop.bundle.event_listener.back_url_redirect_response_listener:
        class: PrestaShopBundle\EventListener\BackUrlRedirectResponseListener
        arguments:
          - '@prestashop.core.uti.back_url_provider'
        tags:
          - { name: kernel.event_listener, event: kernel.response, method: onKernelResponse }

    prestashop.bundle.event_listener.module_guard_listener:
        class: PrestaShopBundle\EventListener\ModuleGuardListener
        arguments:
          - '@prestashop.core.security.folder_guard.vendor'
          - '%modules_dir%'
          - '@logger'
        tags:
          - { name: kernel.event_subscriber }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,6 +89,7 @@
         class: PrestaShopBundle\EventListener\BackUrlRedirectResponseListener
         arguments:
           - '@prestashop.core.uti.back_url_provider'
+          - "@prestashop.adapter.legacy.context"
         tags:
           - { name: kernel.event_listener, event: kernel.response, method: onKernelResponse }
 
```
