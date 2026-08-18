# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 544-584 of the vulnerable file.

        // log auction bid IP
        $system->log('user', 'Bid $' . $bid . '(previous bid was $' . $current_bid . ') on Item', $bidder_id, $id);
    }
    $template->assign_vars(array(
            'PAGE' => 2,
            'BID_HISTORY' => (isset($ARETHEREBIDS)) ? $ARETHEREBIDS : '',
            'TITLE' => $item_title,
            'ID' => $id,
            'BID' => $system->print_money($bid),
            'TQTY' => 0
            ));
}

if (!isset($_POST['action']) || isset($errmsg)) {
    // just set the needed template variables
    $template->assign_vars(array(
            'PAGE' => 1,
            'ERROR' => (isset($errmsg)) ? $errmsg : '',
            'BID_HISTORY' => (isset($ARETHEREBIDS)) ? $ARETHEREBIDS : '',
            'ID' => $id,
            'IMAGE' => (!empty($pict_url_plain)) ? '<img src="getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&fromfile=' . UPLOAD_FOLDER . $id . '/' . $pict_url_plain . '" border="0" align="center">' : '&nbsp;',
            'TITLE' => $item_title,
            'CURRENT_BID' => $system->print_money($cbid),
            'ATYPE' => $atype,
            'BID' => $system->print_money_nosymbol($bid),
            'NEXT_BID' => $system->print_money($next_bid),
            'QTY' => $qty,
            'TQTY' => $aquantity,
            'AGREEMENT' => sprintf($MSG['25_0086'], $system->print_money($qty * $bid)),
            'CURRENCY' => $system->SETTINGS['currency'],

            'B_USERAUTH' => ($system->SETTINGS['usersauth'] == 'y')
            ));
}

include 'header.php';
$template->set_filenames(array(
        'body' => 'bid.tpl'
        ));
$template->display('body');
include 'footer.php';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -561,7 +561,7 @@
             'ERROR' => (isset($errmsg)) ? $errmsg : '',
             'BID_HISTORY' => (isset($ARETHEREBIDS)) ? $ARETHEREBIDS : '',
             'ID' => $id,
-            'IMAGE' => (!empty($pict_url_plain)) ? '<img src="getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&fromfile=' . UPLOAD_FOLDER . $id . '/' . $pict_url_plain . '" border="0" align="center">' : '&nbsp;',
+            'IMAGE' => (!empty($pict_url_plain)) ? '<img src="getthumb.php?w=' . $system->SETTINGS['thumb_show'] . '&auction_id=' . $id . '&fromfile=' . $pict_url_plain . '" border="0" align="center">' : '',
             'TITLE' => $item_title,
             'CURRENT_BID' => $system->print_money($cbid),
             'ATYPE' => $atype,
```
