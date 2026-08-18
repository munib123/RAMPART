# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4338_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4338_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 14-54 of the vulnerable file.

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
use Doctrine\ORM\EntityManagerInterface;
use PrestaShop\Module\ProductComment\Entity\ProductComment;
use PrestaShop\Module\ProductComment\Entity\ProductCommentReport;

class ProductCommentsReportCommentModuleFrontController extends ModuleFrontController
{
    public function display()
    {
        $customerId = (int) $this->context->cookie->id_customer;
        if (!$customerId) {
            $this->ajaxRender(json_encode([
                'success' => false,
                'error' => $this->trans('You need to be logged in to report a review.', [], 'Modules.Productcomments.Shop'),
            ]));

            return false;
        }

        $id_product_comment = (int) Tools::getValue('id_product_comment');

        /** @var EntityManagerInterface $entityManager */
        $entityManager = $this->container->get('doctrine.orm.entity_manager');
        $productCommentEntityRepository = $entityManager->getRepository(ProductComment::class);

        $productComment = $productCommentEntityRepository->findOneById($id_product_comment);
        if (!$productComment) {
            $this->ajaxRender(json_encode([
                'success' => false,
                'error' => $this->trans('Cannot find the requested product review.', [], 'Modules.Productcomments.Shop'),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,12 +31,18 @@
 {
     public function display()
     {
+        header('Content-Type: application/json');
+
         $customerId = (int) $this->context->cookie->id_customer;
         if (!$customerId) {
-            $this->ajaxRender(json_encode([
-                'success' => false,
-                'error' => $this->trans('You need to be logged in to report a review.', [], 'Modules.Productcomments.Shop'),
-            ]));
+            $this->ajaxRender(
+                json_encode(
+                    [
+                        'success' => false,
+                        'error' => $this->trans('You need to be logged in to report a review.', [], 'Modules.Productcomments.Shop'),
+                    ]
+                )
+            );
 
             return false;
         }
@@ -49,10 +55,14 @@
 
         $productComment = $productCommentEntityRepository->findOneById($id_product_comment);
         if (!$productComment) {
-            $this->ajaxRender(json_encode([
-                'success' => false,
-                'error' => $this->trans('Cannot find the requested product review.', [], 'Modules.Productcomments.Shop'),
-            ]));
+            $this->ajaxRender(
+                json_encode(
+                    [
+                        'success' => false,
+                        'error' => $this->trans('Cannot find the requested product review.', [], 'Modules.Productcomments.Shop'),
+                    ]
+                )
+            );
 
             return false;
         }
@@ -63,11 +73,16 @@
             'comment' => $id_product_comment,
             'customerId' => $customerId,
         ]);
+
         if ($productCommentAbuse) {
-            $this->ajaxRender(json_encode([
-                'success' => false,
-                'error' => $this->trans('You already reported this review as abusive.', [], 'Modules.Productcomments.Shop'),
-            ]));
+            $this->ajaxRender(
+                json_encode(
+                    [
+                        'success' => false,
+                        'error' => $this->trans('You already reported this review as abusive.', [], 'Modules.Productcomments.Shop'),
+                    ]
+                )
+            );
 
             return false;
         }
@@ -79,9 +94,13 @@
         $entityManager->persist($productCommentAbuse);
         $entityManager->flush();
 
-        $this->ajaxRender(json_encode([
-            'success' => true,
-            'id_product_comment' => $id_product_comment,
-        ]));
+        $this->ajaxRender(
+            json_encode(
+                [
+                    'success' => true,
+                    'id_product_comment' => $id_product_comment,
+                ]
+            )
+        );
     }
 }
```
