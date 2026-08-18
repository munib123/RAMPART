# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4338_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4338_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

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

class ProductCommentsCommentGradeModuleFrontController extends ModuleFrontController
{
    public function display()
    {
        $idProducts = Tools::getValue('id_products');
        /** @var ProductCommentRepository $productCommentRepository */

        if (!is_array($idProducts)) {
            return $this->ajaxRender(null);
        }

        $productCommentRepository = $this->context->controller->getContainer()->get('product_comment_repository');

        $productsCommentsNb = $productCommentRepository->getCommentsNumberForProducts($idProducts, Configuration::get('PRODUCT_COMMENTS_MODERATE'));
        $averageGrade = $productCommentRepository->getAverageGrades($idProducts, Configuration::get('PRODUCT_COMMENTS_MODERATE'));

        $resultFormated = [];

        foreach ($idProducts as $i => $id) {
            $resultFormated []= [
                'id_product' => $id,
                'comments_nb' => $productsCommentsNb[$id],
                'average_grade' => $averageGrade[$id]
            ];
        }

        $this->ajaxRender(json_encode([
            'products' => $resultFormated
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,8 @@
         $idProducts = Tools::getValue('id_products');
         /** @var ProductCommentRepository $productCommentRepository */
 
+        header('Content-Type: application/json');
+
         if (!is_array($idProducts)) {
             return $this->ajaxRender(null);
         }
@@ -51,8 +53,12 @@
             ];
         }
 
-        $this->ajaxRender(json_encode([
-            'products' => $resultFormated
-        ]));
+        $this->ajaxRender(
+            json_encode(
+                [
+                    'products' => $resultFormated
+                ]
+            )
+        );
     }
 }
```
