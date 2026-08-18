# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 381-421 of the vulnerable file.

    global $system, $DBPrefix, $buy_now_price, $reserve_price, $is_bold, $is_highlighted, $is_featured, $_SESSION, $subtitle, $sellcat2, $relist, $db;

    $query = "SELECT * FROM " . $DBPrefix . "fees ORDER BY type, fee_from ASC";
    $db->direct_query($query);

    $fee_value = 0;
    // set defaults
    $fee_data = array(
        'setup_fee' => 0,
        'featured_fee' => 0,
        'bold_fee' => 0,
        'highlighted_fee' => 0,
        'subtitle_fee' => 0,
        'relist_fee' => 0,
        'reserve_fee' => 0,
        'buynow_fee' => 0,
        'picture_fee' => 0,
        'extracat_fee' => 0
    );
    while ($row = $db->fetch()) {
        if ($minimum_bid >= $row['fee_from'] && $minimum_bid <= $row['fee_to'] && $row['type'] == 'setup') {
            if ($row['fee_type'] == 'flat') {
                $fee_data['setup_fee'] = $row['value'];
                $fee_value = bcadd($fee_value, $row['value'], $system->SETTINGS['moneydecimals']);
            } else {
                $tmp = bcdiv($row['value'], '100', $system->SETTINGS['moneydecimals']);
                $tmp = bcmul($tmp, $minimum_bid, $system->SETTINGS['moneydecimals']);
                $fee_data['setup_fee'] = $tmp;
                $fee_value = bcadd($fee_value, $tmp, $system->SETTINGS['moneydecimals']);
            }
        }
        if ($row['type'] == 'buynow_fee' && $buy_now_price > 0) {
            $fee_data['buynow_fee'] = $row['value'];
            $fee_value = bcadd($fee_value, $row['value'], $system->SETTINGS['moneydecimals']);
        }
        if ($row['type'] == 'reserve_fee' && $reserve_price > 0) {
            $fee_data['reserve_fee'] = $row['value'];
            $fee_value = bcadd($fee_value, $row['value'], $system->SETTINGS['moneydecimals']);
        }
        if ($row['type'] == 'bold_fee' && $is_bold) {
            $fee_data['bold_fee'] = $row['value'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -398,7 +398,7 @@
         'extracat_fee' => 0
     );
     while ($row = $db->fetch()) {
-        if ($minimum_bid >= $row['fee_from'] && $minimum_bid <= $row['fee_to'] && $row['type'] == 'setup') {
+        if ($minimum_bid >= $row['fee_from'] && $minimum_bid <= $row['fee_to'] && $row['type'] == 'setup_fee') {
             if ($row['fee_type'] == 'flat') {
                 $fee_data['setup_fee'] = $row['value'];
                 $fee_value = bcadd($fee_value, $row['value'], $system->SETTINGS['moneydecimals']);
```
