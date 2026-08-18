# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 49-89 of the vulnerable file.

$PAGES = ceil($num_auctions / $system->SETTINGS['perpage']);
if (!isset($PAGES) || $PAGES < 1) {
    $PAGES = 1;
}

$query = "SELECT * FROM " . $DBPrefix . "auctions
		WHERE user = :user_id
		AND closed = 0
		AND suspended = 0
		AND starts <= CURRENT_TIMESTAMP
		ORDER BY ends ASC LIMIT :offset, :perpage";
$params = array();
$params[] = array(':user_id', $user_id, 'int');
$params[] = array(':offset', $OFFSET, 'int');
$params[] = array(':perpage', $system->SETTINGS['perpage'], 'int');
$db->query($query, $params);

$k = 0;
while ($row = $db->fetch()) {
    if (strlen($row['pict_url']) > 0) {
        $row['pict_url'] = $system->SETTINGS['siteurl'] . 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&fromfile=' . UPLOAD_FOLDER . $row['id'] . '/' . $row['pict_url'];
    } else {
        $row['pict_url'] = get_lang_img('nopicture.gif');
    }

    $current_time = new DateTime('now', $dt->UTCtimezone);
    $end_time = new DateTime($row['ends'], $dt->UTCtimezone);
    $difference = $current_time->diff($end_time);

    $template->assign_block_vars('auctions', array(
            'BGCOLOUR' => (!($k % 2)) ? '' : 'class="alt-row"',
            'ID' => $row['id'],
            'PIC_URL' => $row['pict_url'],
            'TITLE' => htmlspecialchars($row['title']),
            'BNIMG' => get_lang_img(($row['bn_only'] == 0) ? 'buy_it_now.gif' : 'bn_only.png'),
            'BNVALUE' => $row['buy_now'],
            'BNFORMAT' => $system->print_money($row['buy_now']),
            'BIDVALUE' => $row['current_bid'],
            'BIDFORMAT' => $system->print_money($row['current_bid']),
            'NUM_BIDS' => $row['num_bids'],
            'TIMELEFT' => $dt->formatTimeLeft($difference),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -66,7 +66,7 @@
 $k = 0;
 while ($row = $db->fetch()) {
     if (strlen($row['pict_url']) > 0) {
-        $row['pict_url'] = $system->SETTINGS['siteurl'] . 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&fromfile=' . UPLOAD_FOLDER . $row['id'] . '/' . $row['pict_url'];
+        $row['pict_url'] = $system->SETTINGS['siteurl'] . 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&auction_id=' . $row['id'] . '&fromfile=' . $row['pict_url'];
     } else {
         $row['pict_url'] = get_lang_img('nopicture.gif');
     }
```
