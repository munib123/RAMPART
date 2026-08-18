# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4363_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4363_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

 *
 * @author    PrestaShop SA and Contributors <contact@prestashop.com>
 * @copyright Since 2007 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 */
use PrestaShop\Module\ProductComment\Repository\ProductCommentRepository;

class ProductCommentsCommentGradeModuleFrontController extends ModuleFrontController
{
    public function display()
    {
        $idProducts = Tools::getValue('id_products');
        /* @var ProductCommentRepository $productCommentRepository */

        header('Content-Type: application/json');

        if (!is_array($idProducts)) {
            return $this->ajaxRender(null);
        }

        $productCommentRepository = $this->context->controller->getContainer()->get('product_comment_repository');

        $productsCommentsNb = $productCommentRepository->getCommentsNumberForProducts($idProducts, Configuration::get('PRODUCT_COMMENTS_MODERATE'));
        $averageGrade = $productCommentRepository->getAverageGrades($idProducts, Configuration::get('PRODUCT_COMMENTS_MODERATE'));

        $resultFormated = [];

        foreach ($idProducts as $i => $id) {
            $resultFormated[] = [
                'id_product' => $id,
                'comments_nb' => $productsCommentsNb[$id],
                'average_grade' => $averageGrade[$id],
            ];
        }

        $this->ajaxRender(
            json_encode(
                [
                    'products' => $resultFormated,
                ]
            )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,8 @@
             return $this->ajaxRender(null);
         }
 
+        $idProducts = array_unique(array_map('intval', $idProducts));
+
         $productCommentRepository = $this->context->controller->getContainer()->get('product_comment_repository');
 
         $productsCommentsNb = $productCommentRepository->getCommentsNumberForProducts($idProducts, Configuration::get('PRODUCT_COMMENTS_MODERATE'));
```
