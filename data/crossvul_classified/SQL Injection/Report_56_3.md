# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 48-88 of the vulnerable file.

if ($PAGES < 1) {
    $PAGES = 1;
}

$query = "SELECT * FROM " . $DBPrefix . "auctions
		WHERE user = :user_id
		AND closed = 1
		ORDER BY ends ASC LIMIT :offset, :perpage";
$params = array();
$params[] = array(':user_id', $user_id, 'int');
$params[] = array(':offset', $OFFSET, 'int');
$params[] = array(':perpage', $system->SETTINGS['perpage'], 'int');
$db->query($query, $params);
$auction_data = $db->fetchall();

foreach ($auction_data as $row) {
    $bid = $row['current_bid'];
    $starting_price = $row['current_bid'];

    if (strlen($row['pict_url']) > 0) {
        $row['pict_url'] = $system->SETTINGS['siteurl'] . 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&fromfile=' . UPLOAD_FOLDER . $row['id'] . '/' . $row['pict_url'];
    } else {
        $row['pict_url'] = get_lang_img('nopicture.gif');
    }

    // number of bids for this auction
    $query = "SELECT bid FROM " . $DBPrefix . "bids WHERE auction = :user_id";
    $params = array();
    $params[] = array(':user_id', $row['id'], 'int');
    $db->query($query, $params);
    $num_bids = $db->numrows();

    $current_time = new DateTime('now', $dt->UTCtimezone);
    $end_time = new DateTime($row['ends'], $dt->UTCtimezone);
    $difference = $current_time->diff($end_time);

    $template->assign_block_vars('auctions', array(
            'BGCOLOUR' => (!($TOTALAUCTIONS % 2)) ? '' : 'class="alt-row"',
            'ID' => $row['id'],
            'PIC_URL' => $row['pict_url'],
            'TITLE' => htmlspecialchars($row['title']),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,7 +65,7 @@
     $starting_price = $row['current_bid'];
 
     if (strlen($row['pict_url']) > 0) {
-        $row['pict_url'] = $system->SETTINGS['siteurl'] . 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&fromfile=' . UPLOAD_FOLDER . $row['id'] . '/' . $row['pict_url'];
+        $row['pict_url'] = $system->SETTINGS['siteurl'] . 'getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&auction_id=' . $row['id'] . '&fromfile=' . $row['pict_url'];
     } else {
         $row['pict_url'] = get_lang_img('nopicture.gif');
     }
```
