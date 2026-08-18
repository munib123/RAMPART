# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4338_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4338_4`)

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
use Doctrine\ORM\EntityManagerInterface;
use PrestaShop\Module\ProductComment\Entity\ProductComment;
use PrestaShop\Module\ProductComment\Entity\ProductCommentUsefulness;
use PrestaShop\Module\ProductComment\Repository\ProductCommentRepository;

class ProductCommentsUpdateCommentUsefulnessModuleFrontController extends ModuleFrontController
{
    public function display()
    {
        if (!Configuration::get('PRODUCT_COMMENTS_USEFULNESS')) {
            $this->ajaxRender(json_encode([
                'success' => false,
                'error' => $this->trans('This feature is not enabled.', [], 'Modules.Productcomments.Shop'),
            ]));

            return false;
        }

        $customerId = (int) $this->context->cookie->id_customer;
        if (!$customerId) {
            $this->ajaxRender(json_encode([
                'success' => false,
                'error' => $this->trans(
                    'You need to be [1]logged in[/1] or [2]create an account[/2] to give your appreciation of a review.',
                    [
                        '[1]' => '<a href="' . $this->context->link->getPageLink('my-account') . '">',
                        '[/1]' => '</a>',
                        '[2]' => '<a href="' . $this->context->link->getPageLink('authentication&create_account=1') . '">',
                        '[/2]' => '</a>',
                    ],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,30 +32,40 @@
 {
     public function display()
     {
+        header('Content-Type: application/json');
+
         if (!Configuration::get('PRODUCT_COMMENTS_USEFULNESS')) {
-            $this->ajaxRender(json_encode([
-                'success' => false,
-                'error' => $this->trans('This feature is not enabled.', [], 'Modules.Productcomments.Shop'),
-            ]));
+            $this->ajaxRender(
+                json_encode(
+                    [
+                        'success' => false,
+                        'error' => $this->trans('This feature is not enabled.', [], 'Modules.Productcomments.Shop'),
+                    ]
+                )
+            );
 
             return false;
         }
 
         $customerId = (int) $this->context->cookie->id_customer;
         if (!$customerId) {
-            $this->ajaxRender(json_encode([
-                'success' => false,
-                'error' => $this->trans(
-                    'You need to be [1]logged in[/1] or [2]create an account[/2] to give your appreciation of a review.',
+            $this->ajaxRender(
+                json_encode(
                     [
-                        '[1]' => '<a href="' . $this->context->link->getPageLink('my-account') . '">',
-                        '[/1]' => '</a>',
-                        '[2]' => '<a href="' . $this->context->link->getPageLink('authentication&create_account=1') . '">',
-                        '[/2]' => '</a>',
-                    ],
-                    'Modules.Productcomments.Shop'
-                ),
-            ]));
+                        'success' => false,
+                        'error' => $this->trans(
+                            'You need to be [1]logged in[/1] or [2]create an account[/2] to give your appreciation of a review.',
+                            [
+                                '[1]' => '<a href="' . $this->context->link->getPageLink('my-account') . '">',
+                                '[/1]' => '</a>',
+                                '[2]' => '<a href="' . $this->context->link->getPageLink('authentication&create_account=1') . '">',
+                                '[/2]' => '</a>',
+                            ],
+                            'Modules.Productcomments.Shop'
+                        ),
+                    ]
+                )
+            );
 
             return false;
         }
@@ -69,10 +79,14 @@
 
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
@@ -100,9 +114,16 @@
         $productCommentRepository = $this->context->controller->getContainer()->get('product_comment_repository');
         $commentUsefulness = $productCommentRepository->getProductCommentUsefulness($id_product_comment);
 
-        $this->ajaxRender(json_encode(array_merge([
-            'success' => true,
-            'id_product_comment' => $id_product_comment,
-        ], $commentUsefulness)));
+        $this->ajaxRender(
+            json_encode(
+                array_merge(
+                    [
+                        'success' => true,
+                        'id_product_comment' => $id_product_comment,
+                    ],
+                    $commentUsefulness
+                )
+            )
+        );
     }
 }
```
