# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 87-127 of the vulnerable file.

$params = array();
$params[] = array(':limit', $system->SETTINGS['homefeaturednumber'], 'int');
$db->query($query, $params);

$i = 0;
while ($row = $db->fetch()) {
    if (strtotime($row['ends']) - time() > 0) {
        $current_time = new DateTime('now', $dt->UTCtimezone);
        $end_time = new DateTime($row['ends'], $dt->UTCtimezone);
        $difference = $current_time->diff($end_time);
        $ends_string = $dt->formatTimeLeft($difference);
    } else {
        $ends_string = $MSG['911'];
    }
    $high_bid = ($row['num_bids'] == 0) ? $row['minimum_bid'] : $row['current_bid'];
    $high_bid = ($row['bn_only']) ? $row['buy_now'] : $high_bid;
    $template->assign_block_vars('featured', array(
            'ENDS' => $ends_string,
            'ID' => $row['id'],
            'BID' => $system->print_money($high_bid),
            'IMAGE' => (!empty($row['pict_url'])) ? 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&amp;fromfile=' . UPLOAD_FOLDER . $row['id'] . '/' . $row['pict_url'] : 'images/email_alerts/default_item_img.jpg',
            'TITLE' => htmlspecialchars($row['title'])
            ));
    $i++;
}

$featured_items = ($i > 0) ? true : false;

// get last created auctions
$query = "SELECT id, title, starts from " . $DBPrefix . "auctions
			WHERE closed = 0 AND suspended = 0
			AND starts <= CURRENT_TIMESTAMP
			ORDER BY starts DESC
			LIMIT :limit";
$params = array();
$params[] = array(':limit', $system->SETTINGS['lastitemsnumber'], 'int');
$db->query($query, $params);

$i = 0;
while ($row = $db->fetch()) {
    $template->assign_block_vars('auc_last', array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,7 +104,7 @@
             'ENDS' => $ends_string,
             'ID' => $row['id'],
             'BID' => $system->print_money($high_bid),
-            'IMAGE' => (!empty($row['pict_url'])) ? 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&amp;fromfile=' . UPLOAD_FOLDER . $row['id'] . '/' . $row['pict_url'] : 'images/email_alerts/default_item_img.jpg',
+            'IMAGE' => (!empty($row['pict_url'])) ? 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&auction_id=' . $row['id'] . '&fromfile=' . $row['pict_url'] : '',
             'TITLE' => htmlspecialchars($row['title'])
             ));
     $i++;
@@ -188,7 +188,7 @@
             'ENDS' => $ends_string,
             'ID' => $row['id'],
             'BID' => $system->print_money($high_bid),
-            'IMAGE' => (!empty($row['pict_url'])) ? 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&amp;fromfile=' . UPLOAD_FOLDER . $row['id'] . '/' . $row['pict_url'] : 'images/email_alerts/default_item_img.jpg',
+            'IMAGE' => (!empty($row['pict_url'])) ? 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&auction_id=' . $row['id'] . '&amp;fromfile=' . $row['pict_url'] : '',
             'TITLE' => htmlspecialchars($row['title'])
             ));
 }
```
