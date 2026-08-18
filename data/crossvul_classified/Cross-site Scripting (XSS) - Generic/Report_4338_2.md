# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4338_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4338_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 16-56 of the vulnerable file.

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
use PrestaShop\Module\ProductComment\Entity\ProductComment;
use PrestaShop\Module\ProductComment\Entity\ProductCommentCriterion;
use PrestaShop\Module\ProductComment\Entity\ProductCommentGrade;
use Doctrine\ORM\EntityManagerInterface;
use PrestaShop\Module\ProductComment\Repository\ProductCommentRepository;

class ProductCommentsPostCommentModuleFrontController extends ModuleFrontController
{
    public function display()
    {
        if (!(int) $this->context->cookie->id_customer && !Configuration::get('PRODUCT_COMMENTS_ALLOW_GUESTS')) {
            $this->ajaxRender(json_encode([
                'success' => false,
                'error' => $this->trans(
                    'You need to be [1]logged in[/1] or [2]create an account[/2] to post your review.',
                    [
                        '[1]' => '<a href="' . $this->context->link->getPageLink('my-account') . '">',
                        '[/1]' => '</a>',
                        '[2]' => '<a href="' . $this->context->link->getPageLink('authentication&create_account=1') . '">',
                        '[/2]' => '</a>',
                    ],
                    'Modules.Productcomments.Shop'
                ),
            ]));

            return false;
        }

        $id_product = (int) Tools::getValue('id_product');
        $comment_title = Tools::getValue('comment_title');
        $comment_content = Tools::getValue('comment_content');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,20 +33,25 @@
 {
     public function display()
     {
+        header('Content-Type: application/json');
         if (!(int) $this->context->cookie->id_customer && !Configuration::get('PRODUCT_COMMENTS_ALLOW_GUESTS')) {
-            $this->ajaxRender(json_encode([
-                'success' => false,
-                'error' => $this->trans(
-                    'You need to be [1]logged in[/1] or [2]create an account[/2] to post your review.',
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
+                            'You need to be [1]logged in[/1] or [2]create an account[/2] to post your review.',
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
@@ -59,12 +64,20 @@
 
         /** @var ProductCommentRepository $productCommentRepository */
         $productCommentRepository = $this->context->controller->getContainer()->get('product_comment_repository');
-        $isPostAllowed = $productCommentRepository->isPostAllowed($id_product, (int) $this->context->cookie->id_customer, (int) $this->context->cookie->id_guest);
+        $isPostAllowed = $productCommentRepository->isPostAllowed(
+            $id_product,
+            (int) $this->context->cookie->id_customer,
+            (int) $this->context->cookie->id_guest
+        );
         if (!$isPostAllowed) {
-            $this->ajaxRender(json_encode([
-                'success' => false,
-                'error' => $this->trans('You are not allowed to post a review at the moment, please try again later.', [], 'Modules.Productcomments.Shop'),
-            ]));
+            $this->ajaxRender(
+                json_encode(
+                    [
+                        'success' => false,
+                        'error' => $this->trans('You are not allowed to post a review at the moment, please try again later.', [], 'Modules.Productcomments.Shop'),
+                    ]
+                )
+            );
 
             return false;
         }
@@ -87,21 +100,30 @@
         $this->addCommentGrades($productComment, $criterions);
 
         //Validate comment
-        if (!empty($errors = $this->validateComment($productComment))) {
-            $this->ajaxRender(json_encode([
-                'success' => false,
-                'errors' => $errors,
-            ]));
+        $errors = $this->validateComment($productComment);
+        if (!empty($errors)) {
+            $this->ajaxRender(
+                json_encode(
+                    [
+                        'success' => false,
+                        'errors' => $errors,
+                    ]
+                )
+            );
 
             return false;
         }
 
         $entityManager->flush();
 
-        $this->ajaxRender(json_encode([
-            'success' => true,
-            'product_comment' => $productComment->toArray(),
-        ]));
+        $this->ajaxRender(
+            json_encode(
+                [
+                    'success' => true,
+                    'product_comment' => $productComment->toArray(),
+                ]
+            )
+        );
     }
 
     /**
@@ -116,6 +138,7 @@
         $entityManager = $this->container->get('doctrine.orm.entity_manager');
         $criterionRepository = $entityManager->getRepository(ProductCommentCriterion::class);
         $averageGrade = 0;
+
         foreach ($criterions as $criterionId => $grade) {
             $criterion = $criterionRepository->findOneById($criterionId);
             $criterionGrade = new ProductCommentGrade(
@@ -123,9 +146,11 @@
                 $criterion,
                 $grade
             );
+
             $entityManager->persist($criterionGrade);
             $averageGrade += $grade;
         }
+
         $averageGrade /= count($criterions);
         $productComment->setGrade($averageGrade);
     }
```
