# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4447_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4447_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 399-439 of the vulnerable file.

                'title'              => trans('front.checkout_title'),
                'cart'               => Cart::instance('default')->content(),
                'dataTotal'          => $dataTotal,
                'paymentMethodData'  => $paymentMethodData,
                'shippingMethodData' => $shippingMethodData,
                'shippingAddress'    => $shippingAddress,
                'attributesGroup'    => ShopAttributeGroup::getListAll(),
                'layout_page'        => 'shop_cart',
            ]
        );
    }

    /**
     * Add to cart by method post, always use in the product page detail
     * 
     * @return [redirect]
     */
    public function addToCart()
    {
        $data      = request()->all();
        $productId = $data['product_id'];
        $qty       = $data['qty'] ?? 0;
        $storeId   = $data['storeId'] ?? config('app.storeId');

        //Process attribute price
        $formAttr = $data['form_attr'] ?? null;
        $optionPrice  = 0;
        if ($formAttr) {
            foreach ($formAttr as $key => $attr) {
                $optionPrice += explode('__', $attr)[1] ??0;
            }
        }
        //End addtribute price

        $product = (new ShopProduct)->getDetail($productId, null, $storeId);

        if (!$product) {
            return response()->json(
                [
                    'error' => 1,
                    'msg' => trans('front.notfound'),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -416,6 +416,10 @@
     public function addToCart()
     {
         $data      = request()->all();
+        
+        //Process escape
+        $data      = sc_clean($data);
+
         $productId = $data['product_id'];
         $qty       = $data['qty'] ?? 0;
         $storeId   = $data['storeId'] ?? config('app.storeId');
@@ -574,7 +578,6 @@
         //Set session info order
         session(['dataOrder' => $dataOrder]);
         session(['arrCartDetail' => $arrCartDetail]);
-
         //Create new order
         $newOrder = (new ShopOrder)->createOrder($dataOrder, $dataTotal, $arrCartDetail);
 
@@ -597,6 +600,10 @@
                 'country'         => $shippingAddress['country'] ?? '',
                 'phone'           => $shippingAddress['phone'] ?? '',
             ];
+
+            //Process escape
+            $addressNew = sc_clean($addressNew);
+
             ShopCustomer::find($uID)->addresses()->save(new ShopCustomerAddress(sc_clean($addressNew)));
             session()->forget('address_process'); //destroy address_process
         }
```
