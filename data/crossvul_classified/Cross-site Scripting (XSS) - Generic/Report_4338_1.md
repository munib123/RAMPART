# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4338_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4338_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 58-80 of the vulnerable file.

                \IntlDateFormatter::SHORT
            );
            $productComment['customer_name'] = htmlentities($productComment['customer_name']);
            $productComment['title'] = htmlentities($productComment['title']);
            $productComment['content'] = htmlentities($productComment['content']);
            $productComment['date_add'] = $dateFormatter->format($dateAdd);

            if($isLastNameAnynomus) {
                $productComment['lastname'] = substr($productComment['lastname'], 0, 1) . '.';
            }

            $usefulness = $productCommentRepository->getProductCommentUsefulness($productComment['id_product_comment']);
            $productComment = array_merge($productComment, $usefulness);
            if (empty($productComment['customer_name']) && !isset($productComment['firstname']) && !isset($productComment['lastname'])) {
                $productComment['customer_name'] = $this->trans('Deleted account', [], 'Modules.Productcomments.Shop');
            }

            $responseArray['comments'][] = $productComment;
        }

        $this->ajaxRender(json_encode($responseArray));
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,6 +75,11 @@
             $responseArray['comments'][] = $productComment;
         }
 
-        $this->ajaxRender(json_encode($responseArray));
+        header('Content-Type: application/json');
+        $this->ajaxRender(
+            json_encode(
+                $responseArray
+            )
+        );
     }
 }
```
