# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4363_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4363_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 161-201 of the vulnerable file.

    {
        if (Tools::isSubmit('submitModerate')) {
            Configuration::updateValue('PRODUCT_COMMENTS_MODERATE', (int) Tools::getValue('PRODUCT_COMMENTS_MODERATE'));
            Configuration::updateValue('PRODUCT_COMMENTS_ALLOW_GUESTS', (int) Tools::getValue('PRODUCT_COMMENTS_ALLOW_GUESTS'));
            Configuration::updateValue('PRODUCT_COMMENTS_USEFULNESS', (int) Tools::getValue('PRODUCT_COMMENTS_USEFULNESS'));
            Configuration::updateValue('PRODUCT_COMMENTS_COMMENTS_PER_PAGE', (int) Tools::getValue('PRODUCT_COMMENTS_COMMENTS_PER_PAGE'));
            Configuration::updateValue('PRODUCT_COMMENTS_ANONYMISATION', (int) Tools::getValue('PRODUCT_COMMENTS_ANONYMISATION'));
            Configuration::updateValue('PRODUCT_COMMENTS_MINIMAL_TIME', (int) Tools::getValue('PRODUCT_COMMENTS_MINIMAL_TIME'));
            $this->_html .= '<div class="conf confirm alert alert-success">' . $this->trans('Settings updated', [], 'Modules.Productcomments.Admin') . '</div>';
        } elseif (Tools::isSubmit('productcomments')) {
            $id_product_comment = (int) Tools::getValue('id_product_comment');
            $comment = new ProductComment($id_product_comment);
            $comment->validate();
            ProductComment::deleteReports($id_product_comment);
        } elseif (Tools::isSubmit('deleteproductcomments')) {
            $id_product_comment = (int) Tools::getValue('id_product_comment');
            $comment = new ProductComment($id_product_comment);
            $comment->delete();
        } elseif (Tools::isSubmit('submitEditCriterion')) {
            $criterion = new ProductCommentCriterion((int) Tools::getValue('id_product_comment_criterion'));
            $criterion->id_product_comment_criterion_type = Tools::getValue('id_product_comment_criterion_type');
            $criterion->active = Tools::getValue('active');

            $languages = Language::getLanguages();
            $name = [];
            foreach ($languages as $key => $value) {
                $name[$value['id_lang']] = Tools::getValue('name_' . $value['id_lang']);
            }
            $criterion->name = $name;

            if (!$criterion->validateFields(false) || !$criterion->validateFieldsLang(false)) {
                $this->_html .= '<div class="conf confirm alert alert-danger">' . $this->trans('The criterion cannot be saved', [], 'Modules.Productcomments.Admin') . '</div>';
            } else {
                $criterion->save();

                // Clear before reinserting data
                $criterion->deleteCategories();
                $criterion->deleteProducts();
                if ($criterion->id_product_comment_criterion_type == 2) {
                    if ($categories = Tools::getValue('categoryBox')) {
                        if (count($categories)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -178,7 +178,7 @@
             $comment->delete();
         } elseif (Tools::isSubmit('submitEditCriterion')) {
             $criterion = new ProductCommentCriterion((int) Tools::getValue('id_product_comment_criterion'));
-            $criterion->id_product_comment_criterion_type = Tools::getValue('id_product_comment_criterion_type');
+            $criterion->id_product_comment_criterion_type = (int) Tools::getValue('id_product_comment_criterion_type');
             $criterion->active = Tools::getValue('active');
 
             $languages = Language::getLanguages();
```
