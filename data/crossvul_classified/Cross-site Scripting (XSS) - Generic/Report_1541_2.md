# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1541_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1541_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 14-35 of the vulnerable file.

    <input type="hidden" name="a" value="search" />
    <input type="hidden" name="active_project" value="<?php echo active_project()->getId() ?>" />
    <?php echo submit_button(lang('search')); ?>
    <?php echo lang('search hint'); ?>
  </form>
</div>

<?php if (isset($search_results) && is_array($search_results) && count($search_results)) { ?>
<p><?php echo lang('search result description', $pagination->countItemsOnPage($current_page), $pagination->getTotalItems(), clean($search_string)) ?>:</p>
<ul>
<?php foreach ($search_results as $search_result) { ?>
  <li><?php echo clean($search_result->getObjectTypeName()) ?>: <a href="<?php echo $search_result->getObjectUrl() ?>"><?php echo clean($search_result->getObjectName()) ?> | <?php echo implode(' / ', clean($search_result->getObjectPath())) ?></a></li>
<?php } // foreach ?>
</ul>

<?php if (isset($pagination) && ($pagination instanceof DataPagination)) { ?>
<?php echo advanced_pagination($pagination, active_project()->getSearchUrl($search_string, '#PAGE#')); ?>
<?php } // if ?>

<?php } else { ?>
<p><?php echo lang('no search result for', $search_string) ?></p>
<?php } // if ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,5 +31,5 @@
 <?php } // if ?>
 
 <?php } else { ?>
-<p><?php echo lang('no search result for', $search_string) ?></p>
+<p><?php echo lang('no search result for', clean($search_string)) ?></p>
 <?php } // if ?>
```
