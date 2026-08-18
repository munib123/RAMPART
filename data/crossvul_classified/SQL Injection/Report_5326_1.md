# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5326_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5326_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 57-97 of the vulnerable file.

        $product_type = isset($this->params['product_type']) ? $this->params['product_type'] : 'product';
        $product      = new product();

        //if we're trying to add a parent product ONLY, then we redirect to it's show view
        $c = new stdClass();
        if (isset($this->params['product_id']) && empty($this->params['children'])) $c = $product->find('first', 'parent_id=' . $this->params['product_id']);
        if (!empty($c->id)) {
            flash('message', gt("Please select a product and quantity from the options listed below to add to your cart."));
            redirect_to(array('controller'=> 'store', 'action'=> 'show', 'id'=> $this->params['product_id']));
        }

        //check for multiple product adding
        if (isset($this->params['prod-quantity'])) {
            //we are adding multiple children, so we approach a bit different
            //we'll send over the product_id of the parent, along with id's and quantities of children we're adding

            foreach ($this->params['prod-quantity'] as $qkey=> &$quantity) {
                if (in_array($qkey, $this->params['prod-check'])) {
                    //this might not be working...FJD
                    $child = new $product_type($qkey);
                    /*if ($quantity < $child->minimum_order_quantity)                       
                    {
                        flash('message', $child->title . " - " . $child->model . " has a minimum order quantity of " . $child->minimum_order_quantity . 
                        '. Your quantity has been adjusted accordingly.');
                        $quantity = $child->minimum_order_quantity;
                        
                    }*/
                    $this->params['children'][$qkey] = $quantity;
                }
                if (isset($child)) $this->params['product_id'] = $child->parent_id;
            }
        }

        $product = new $product_type($this->params['product_id'], true, true); //need true here?

        //Check the Main Product quantity
        if (isset($this->params['quantity'])) {
            if (((int)$this->params['quantity']) < $product->minimum_order_quantity) {
                flash('message', gt("Please enter a quantity equal or greater than the minimum order quantity."));
                redirect_to(array('controller'=> 'store', 'action'=> 'show', 'id'=> $this->params['product_id']));
            } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,12 +74,12 @@
                 if (in_array($qkey, $this->params['prod-check'])) {
                     //this might not be working...FJD
                     $child = new $product_type($qkey);
-                    /*if ($quantity < $child->minimum_order_quantity)                       
+                    /*if ($quantity < $child->minimum_order_quantity)
                     {
-                        flash('message', $child->title . " - " . $child->model . " has a minimum order quantity of " . $child->minimum_order_quantity . 
+                        flash('message', $child->title . " - " . $child->model . " has a minimum order quantity of " . $child->minimum_order_quantity .
                         '. Your quantity has been adjusted accordingly.');
                         $quantity = $child->minimum_order_quantity;
-                        
+
                     }*/
                     $this->params['children'][$qkey] = $quantity;
                 }
@@ -171,7 +171,7 @@
             $item    = new orderitem($id);
             $updates = new stdClass();
             if (!empty($item->id)) {
-                //$newqty = $item->product->updateQuantity($this->params['value']);                  
+                //$newqty = $item->product->updateQuantity($this->params['value']);
                 $newqty = $item->product->updateQuantity($this->params['value']);
                 if ($newqty > $item->product->quantity) {
                     if ($item->product->availability_type == 1) {
@@ -217,10 +217,10 @@
                     if ($orderItem->product_id == $item->product_id) $qCheck += $orderItem->quantity;
                 }
                 //eDebug("Done",true);
-                //}                           
-                /*eDebug($item->quantity);   
-                eDebug($item->product->quantity); 
-                eDebug($qCheck);                  
+                //}
+                /*eDebug($item->quantity);
+                eDebug($item->product->quantity);
+                eDebug($qCheck);
                 eDebug($newqty,true);  */
                 //check minimum quantity
                 $qtyMessage = '';
@@ -243,7 +243,7 @@
                         //$updates->message = 'Only '.$item->product->quantity.' '.$item->products_name.' are currently in stock. Shipping may be delayed on the other '.$diff;
                     } elseif ($item->product->availability_type == 2) {
                         flash('error', $item->products_name . ' ' . gt('only has') . ' ' . $item->product->quantity . ' ' . gt('on hand. You can not add any more than that to your cart.'));
-                        /*$updates->message = $item->products_name.' only has '.$item->product->quantity.' on hand. You can not add any more to your cart.';                        
+                        /*$updates->message = $item->products_name.' only has '.$item->product->quantity.' on hand. You can not add any more to your cart.';
                         $updates->cart_total = '$'.number_format($order->getCartTotal(), 2);
                         $updates->item_total = '$'.number_format($item->quantity*$item->products_price, 2);
                         $updates->item_id = $id;
@@ -302,7 +302,7 @@
 
             //eDebug($order,true);
             //check to see if we have calculate shipping yet - if shipping_total_before_discounts is set
-            //to something other than 0, then we have, but we'll set the estimtae to shipping_total to 
+            //to something other than 0, then we have, but we'll set the estimtae to shipping_total to
             //accomodate any applied discounts
             //if (!empty($order->shipping_total_before_discounts))
             //{
@@ -310,7 +310,7 @@
             //}
             //otherwise we'll grab an estimate
             //else
-            //{    
+            //{
             //$estimated_shipping = shipping::estimateShipping($order);
             /* $shipping = new shipping();
           $shipping->getRates();
@@ -332,7 +332,7 @@
                 ));
                 $discounts = null;
             } else {
-                // get all current discount codes that are valid and applied                
+                // get all current discount codes that are valid and applied
                 $discounts = $order->validateDiscounts();
             }
         } else {
@@ -703,7 +703,7 @@
         if (empty($result->errorCode)) {
             // if ($result->errorCode === "0" || $result->errorCode === 0)
             // {
-            // save out the cart total to the database		
+            // save out the cart total to the database
             $billing->billingmethod->update(array('billing_cost'=> $order->grand_total));
 
             // set the invoice number and purchase date in the order table..this finializes the order
@@ -1069,11 +1069,11 @@
         //this will change once we allow more than one coupon code
 
         $discount = new discounts();
-        $discount = $discount->getCouponByName($this->params['coupon_code']);
+        $discount = $discount->getCouponByName(expString::escape($this->params['coupon_code']));
 
         if (empty($discount)) {
             flash('error', gt("This discount code you entered does not exist."));
-            //redirect_to(array('controller'=>'cart', 'action'=>'checkout'));       
+            //redirect_to(array('controller'=>'cart', 'action'=>'checkout'));
             expHistory::back();
         }
 
@@ -1100,7 +1100,7 @@
         } else {
             flash('error', $validateDiscountMessage);
         }
-        //redirect_to(array('controller'=>'cart', 'action'=>'checkout'));                           
+        //redirect_to(array('controller'=>'cart', 'action'=>'checkout'));
         expHistory::back();
     }
 
@@ -1141,11 +1141,11 @@
     //this is ran after we alter the quantity of the cart, including
     //delete items or runing the updatequantity action
     private function rebuildCart() {
-        //group items by type and id               
+        //group items by type and id
         //since we can have the same product in different items (options and quantity discount)
         //remove items and readd?
         global $order;
-        //eDebug($order,true); 
+        //eDebug($order,true);
         $items = $order->orderitem;
         foreach ($order->orderitem as $item) {
             $item->delete();
@@ -1185,12 +1185,12 @@
         }
         $order->save();
         /*eDebug($items);
-        
-        
-        $options = array();  
+
+
+        $options = array();
         foreach ($this->optiongroup as $og) {
             if ($og->required && empty($params['options'][$og->id][0])) {
-                
+
                 flash('error', $this->title.' '.gt('requires some options to be selected before you can add it to your cart.'));
                 redirect_to(array('controller'=>store, 'action'=>'show', 'id'=>$this->id));
             }
@@ -1198,7 +1198,7 @@
                 foreach ($params['options'][$og->id] as $opt_id) {
                     $selected_option = new option($opt_id);
                     $cost = $selected_option->modtype == '$' ? $selected_option->amount :  $this->getBasePrice() * ($selected_option->amount * .01);
-                    $cost = $selected_option->updown == '+' ? $cost : $cost * -1;                      
+                    $cost = $selected_option->updown == '+' ? $cost : $cost * -1;
                     $price += $cost;
                     $options[] = array($selected_option->id,$selected_option->title,$selected_option->modtype,$selected_option->updown,$selected_option->amount);
                 }
@@ -1212,7 +1212,7 @@
         //eDebug($item, true);
         $item->products_price = $price;
         $item->options = serialize($options);
-        
+
         $sm = $order->getCurrentShippingMethod();
         $item->shippingmethods_id = $sm->id;
... (diff truncated)
```
