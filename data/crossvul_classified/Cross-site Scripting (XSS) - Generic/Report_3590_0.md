# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3590_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3590_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 40-80 of the vulnerable file.


<?php
      }
?>

      <tr>
        <td valign="top" width="60"><?php echo HTML::button(array('href' => OSCOM::getLink(null, null, 'Delete=' . $products['item_id'], 'SSL'), 'icon' => 'trash', 'title' => OSCOM::getDef('button_delete'))); ?></td>
        <td valign="top">

<?php
      echo HTML::link(OSCOM::getLink(null, 'Products', $products['keyword']), '<b>' . $products['name'] . '</b>');

      if ( (STOCK_CHECK == '1') && ($OSCOM_ShoppingCart->isInStock($products['item_id']) === false) ) {
        echo '<span class="markProductOutOfStock">' . STOCK_MARK_PRODUCT_OUT_OF_STOCK . '</span>';
      }

// HPDL      echo '&nbsp;(Top Category)';

      if ( $OSCOM_ShoppingCart->isVariant($products['item_id']) ) {
        foreach ( $OSCOM_ShoppingCart->getVariant($products['item_id']) as $variant) {
          echo '<br />- ' . $variant['group_title'] . ': ' . $variant['value_title'];
        }
      }
?>

        </td>
        <td valign="top"><?php echo HTML::inputField('products[' . $products['item_id'] . ']', $products['quantity'], 'size="4"'); ?> <a href="#" onclick="document.shopping_cart.submit(); return false;">update</a></td>
        <td valign="top" align="right"><?php echo '<b>' . $OSCOM_Currencies->displayPrice($products['price'], $products['tax_class_id'], $products['quantity']) . '</b>'; ?></td>
      </tr>

<?php
    }
?>

    </table>
  </div>

  </form>

  <table border="0" width="100%" cellspacing="0" cellpadding="2">

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,7 +57,7 @@
 
       if ( $OSCOM_ShoppingCart->isVariant($products['item_id']) ) {
         foreach ( $OSCOM_ShoppingCart->getVariant($products['item_id']) as $variant) {
-          echo '<br />- ' . $variant['group_title'] . ': ' . $variant['value_title'];
+          echo '<br />- ' . $variant['group_title'] . ': ' . HTML::outputProtected($variant['value_title']);
         }
       }
 ?>
```
