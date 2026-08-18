# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 3893_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3893_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 91-131 of the vulnerable file.

    	if(cart!=null) {
    		shoppingCartService.deleteCart(cart);
    	}
    }
    
    @Override
    public void deleteShoppingCart(final String code, final MerchantStore store) throws Exception {
    	ShoppingCart cart = shoppingCartService.getByCode(code, store);
    	if(cart!=null) {
    		shoppingCartService.deleteCart(cart);
    	}
    }

    @Override
    public ShoppingCartData addItemsToShoppingCart( final ShoppingCartData shoppingCartData,
                                                    final ShoppingCartItem item, final MerchantStore store, final Language language,final Customer customer )
        throws Exception
    {

        ShoppingCart cartModel = null;
        
        /**
         * Sometimes a user logs in and a shopping cart is present in db (shoppingCartData
         * but ui has no cookie with shopping cart code so the cart code will have
         * to be added to the item in order to process add to cart normally
         */
        if(shoppingCartData != null && StringUtils.isBlank(item.getCode())) {
        	item.setCode(shoppingCartData.getCode());
        }
        
        
        if ( !StringUtils.isBlank( item.getCode() ) )
        {
            // get it from the db
            cartModel = getShoppingCartModel( item.getCode(), store );
            if ( cartModel == null )
            {
                cartModel = createCartModel( shoppingCartData.getCode(), store,customer );
            }

        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -108,7 +108,7 @@
     {
 
         ShoppingCart cartModel = null;
-        
+        if(item.getQuantity() < 1) item.setQuantity(1);
         /**
          * Sometimes a user logs in and a shopping cart is present in db (shoppingCartData
          * but ui has no cookie with shopping cart code so the cart code will have
@@ -216,7 +216,7 @@
         }
         	
         for(ProductAvailability availability : availabilities) {
-        	if(availability.getProductQuantity() == null || availability.getProductQuantity().intValue() ==0) {
+        	if(availability.getProductQuantity() == null || availability.getProductQuantity().intValue() <= 0) {
                 throw new Exception( "Item with id " + product.getId() + " is not available");
         	}
         }
@@ -288,7 +288,7 @@
         }
         	
         for(ProductAvailability availability : availabilities) {
-        	if(availability.getProductQuantity() == null || availability.getProductQuantity().intValue() ==0) {
+        	if(availability.getProductQuantity() == null || availability.getProductQuantity().intValue() <= 0) {
                 throw new Exception( "Item with id " + product.getId() + " is not available");
         	}
         }
@@ -554,8 +554,7 @@
         return null;
     }
     
-    @SuppressWarnings("unchecked")
-	@Override
+    @Override
     public ShoppingCartData updateCartItems( final List<ShoppingCartItem> shoppingCartItems, final MerchantStore store, final Language language )
             throws Exception
         {
@@ -720,7 +719,6 @@
 	}
 	
 
-	@SuppressWarnings("unchecked")
 	@Override
 	public void removeShoppingCartItem(String cartCode, Long productId,
 	      MerchantStore merchant, Language language) throws Exception {
@@ -914,7 +912,7 @@
 		
 		Validate.notNull(customer,"Customer cannot be null");
 		Validate.notNull(customer.getId(),"Customer.id cannot be null or empty");
-		
+		if(item.getQuantity() < 1) item.setQuantity(1);
 		//Check if customer has an existing shopping cart
 		ShoppingCart cartModel = shoppingCartService.getByCustomer(customer);
 		
```
