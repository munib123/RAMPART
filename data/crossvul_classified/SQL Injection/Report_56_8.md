# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 449-489 of the vulnerable file.

}

$bn_link = (!$has_ended) ? ' <a href="' . $system->SETTINGS['siteurl'] . 'buy_now.php?id=' . $id . '"><img border="0" align="absbottom" alt="' . $MSG['496'] . '" src="' . get_lang_img('buy_it_now.gif') . '"></a>' : '';

$page_title = htmlspecialchars($auction_data['title']);

$shipping = '';
if ($auction_data['shipping'] == 1) {
    $shipping = $MSG['031'];
} elseif ($auction_data['shipping'] == 2) {
    $shipping = $MSG['032'];
} elseif ($auction_data['shipping'] == 3) {
    $shipping = $MSG['867'];
}

$template->assign_vars(array(
        'ID' => $auction_data['id'],
        'TITLE' => htmlspecialchars($auction_data['title']),
        'SUBTITLE' => htmlspecialchars($auction_data['subtitle']),
        'AUCTION_DESCRIPTION' => $auction_data['description'],
        'PIC_URL' => UPLOAD_FOLDER . $id . '/' . $auction_data['pict_url'],
        'SHIPPING_COST' => ($auction_data['shipping_cost'] > 0) ? $system->print_money($auction_data['shipping_cost']) : $MSG['1152'],
        'ADDITIONAL_SHIPPING_COST' => $system->print_money($auction_data['additional_shipping_cost']),
        'COUNTRY' => $auction_data['country'],
        'CITY' => $auction_data['city'],
        'ZIP' => $auction_data['zip'],
        'QTY' => $auction_data['quantity'],
        'ENDS' => $ending_time,
        'ENDS_IN' => (strtotime($ends) - time()),
        'STARTTIME' => $dt->printDateTz($start),
        'ENDTIME' => $dt->printDateTz($ends),
        'BUYNOW1' => $auction_data['buy_now'],
        'BUYNOW2' => ($auction_data['buy_now'] > 0) ? $system->print_money($auction_data['buy_now']) . $bn_link : $system->print_money($auction_data['buy_now']),
        'NUMBIDS' => $num_bids,
        'MINBID' => $min_bid,
        'MAXBID' => $high_bid,
        'NEXTBID' => $next_bid,
        'INTERNATIONAL' => ($auction_data['international']) ? $MSG['033'] : $MSG['043'],
        'SHIPPING' => $shipping,
        'SHIPPINGTERMS' => nl2br(htmlspecialchars($auction_data['shipping_terms'])),
        'PAYMENTS' => $payment_methods,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -466,7 +466,7 @@
         'TITLE' => htmlspecialchars($auction_data['title']),
         'SUBTITLE' => htmlspecialchars($auction_data['subtitle']),
         'AUCTION_DESCRIPTION' => $auction_data['description'],
-        'PIC_URL' => UPLOAD_FOLDER . $id . '/' . $auction_data['pict_url'],
+        'PIC_URL' => $auction_data['pict_url'],
         'SHIPPING_COST' => ($auction_data['shipping_cost'] > 0) ? $system->print_money($auction_data['shipping_cost']) : $MSG['1152'],
         'ADDITIONAL_SHIPPING_COST' => $system->print_money($auction_data['additional_shipping_cost']),
         'COUNTRY' => $auction_data['country'],
```
