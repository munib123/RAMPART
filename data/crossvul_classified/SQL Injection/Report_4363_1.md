# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4363_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4363_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 12-53 of the vulnerable file.

 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@prestashop.com so we can send you a copy immediately.
 *
 * DISCLAIMER
 *
 * Do not edit or add to this file if you wish to upgrade PrestaShop to newer
 * versions in the future. If you wish to customize PrestaShop for your
 * needs please refer to https://devdocs.prestashop.com/ for more information.
 *
 * @author    PrestaShop SA and Contributors <contact@prestashop.com>
 * @copyright Since 2007 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 */
use PrestaShop\Module\ProductComment\Repository\ProductCommentRepository;

class ProductCommentsListCommentsModuleFrontController extends ModuleFrontController
{
    public function display()
    {
        $idProduct = Tools::getValue('id_product');
        $page = Tools::getValue('page', 1);
        $isLastNameAnynomus = Configuration::get('PRODUCT_COMMENTS_ANONYMISATION');
        /** @var ProductCommentRepository $productCommentRepository */
        $productCommentRepository = $this->context->controller->getContainer()->get('product_comment_repository');

        $productComments = $productCommentRepository->paginate(
            $idProduct,
            $page,
            (int) Configuration::get('PRODUCT_COMMENTS_COMMENTS_PER_PAGE'),
            (bool) Configuration::get('PRODUCT_COMMENTS_MODERATE')
        );
        $productCommentsNb = $productCommentRepository->getCommentsNumber(
            $idProduct,
            (bool) Configuration::get('PRODUCT_COMMENTS_MODERATE')
        );

        $responseArray = [
            'comments_nb' => $productCommentsNb,
            'comments_per_page' => Configuration::get('PRODUCT_COMMENTS_COMMENTS_PER_PAGE'),
            'comments' => [],
        ];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,8 +29,8 @@
 {
     public function display()
     {
-        $idProduct = Tools::getValue('id_product');
-        $page = Tools::getValue('page', 1);
+        $idProduct = (int) Tools::getValue('id_product');
+        $page = (int) Tools::getValue('page', 1);
         $isLastNameAnynomus = Configuration::get('PRODUCT_COMMENTS_ANONYMISATION');
         /** @var ProductCommentRepository $productCommentRepository */
         $productCommentRepository = $this->context->controller->getContainer()->get('product_comment_repository');
```
