# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3590_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3590_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 67-107 of the vulnerable file.

?>

              <tr>
                <td colspan="3"><?php echo '<b>' . OSCOM::getDef('order_products_title') . '</b> ' . HTML::link(OSCOM::getLink(null, 'Cart', null, 'SSL'), '<span class="orderEdit">' . OSCOM::getDef('order_text_edit_title') . '</span>'); ?></td>
              </tr>

<?php
  }

  foreach ( $OSCOM_ShoppingCart->getProducts() as $products ) {
    echo '              <tr>' . "\n" .
         '                <td align="right" valign="top" width="30">' . $products['quantity'] . '&nbsp;x&nbsp;</td>' . "\n" .
         '                <td valign="top">' . $products['name'];

    if ( (STOCK_CHECK == '1') && !$OSCOM_ShoppingCart->isInStock($products['item_id']) ) {
      echo '<span class="markProductOutOfStock">' . STOCK_MARK_PRODUCT_OUT_OF_STOCK . '</span>';
    }

    if ( $OSCOM_ShoppingCart->isVariant($products['item_id']) ) {
      foreach ( $OSCOM_ShoppingCart->getVariant($products['item_id']) as $variant) {
        echo '<br />- ' . $variant['group_title'] . ': ' . $variant['value_title'];
      }
    }

    echo '</td>' . "\n";

    if ( $OSCOM_ShoppingCart->numberOfTaxGroups() > 1 ) {
      echo '                <td valign="top" align="right">' . Tax::displayTaxRateValue($products['tax']) . '</td>' . "\n";
    }

    echo '                <td align="right" valign="top">' . $OSCOM_Currencies->displayPrice($products['price'], $products['tax_class_id'], $products['quantity']) . '</td>' . "\n" .
         '              </tr>' . "\n";
  }
?>

            </table>

            <p>&nbsp;</p>

            <table border="0" width="100%" cellspacing="0" cellpadding="2">

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,7 +84,7 @@
 
     if ( $OSCOM_ShoppingCart->isVariant($products['item_id']) ) {
       foreach ( $OSCOM_ShoppingCart->getVariant($products['item_id']) as $variant) {
-        echo '<br />- ' . $variant['group_title'] . ': ' . $variant['value_title'];
+        echo '<br />- ' . $variant['group_title'] . ': ' . HTML::outputProtected($variant['value_title']);
       }
     }
 
```
