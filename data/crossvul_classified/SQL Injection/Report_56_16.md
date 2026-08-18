# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_16
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_16`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 187-228 of the vulnerable file.

          AND (num_bids = 0 OR (num_bids > 0 AND current_bid < reserve_price AND sold = 'n'))";
$params = array();
$params[] = array(':user_id', $user->user_data['id'], 'int');
$db->query($query, $params);
$TOTALAUCTIONS = $db->result('COUNT');

if (!isset($_GET['PAGE']) || $_GET['PAGE'] == 1) {
    $OFFSET = 0;
    $PAGE = 1;
} else {
    $PAGE = intval($_GET['PAGE']);
    $OFFSET = ($PAGE - 1) * $system->SETTINGS['perpage'];
}

$PAGES = ($TOTALAUCTIONS == 0) ? 1 : ceil($TOTALAUCTIONS / $system->SETTINGS['perpage']);
// Handle columns sorting variables
if (!isset($_SESSION['ca_ord']) && empty($_GET['ca_ord'])) {
    $_SESSION['ca_ord'] = 'title';
    $_SESSION['ca_type'] = 'asc';
} elseif (!empty($_GET['ca_ord'])) {
    $_SESSION['ca_ord'] = $_GET['ca_ord'];
    $_SESSION['ca_type'] = $_GET['ca_type'];
} elseif (isset($_SESSION['ca_ord']) && empty($_GET['ca_ord'])) {
    $_SESSION['ca_nexttype'] = $_SESSION['ca_type'];
}

if (!isset($_SESSION['ca_nexttype']) || $_SESSION['ca_nexttype'] == 'desc') {
    $_SESSION['ca_nexttype'] = 'asc';
} else {
    $_SESSION['ca_nexttype'] = 'desc';
}

if (!isset($_SESSION['ca_type']) || $_SESSION['ca_type'] == 'desc') {
    $_SESSION['ca_type_img'] = '<img src="images/arrow_up.gif" align="center" hspace="2" border="0">';
} else {
    $_SESSION['ca_type_img'] = '<img src="images/arrow_down.gif" align="center" hspace="2" border="0">';
}

$query = "SELECT *  FROM " . $DBPrefix . "auctions
	WHERE user = :user_id
	AND closed = 1 AND suspended = 0
	AND (num_bids = 0 OR (num_bids > 0 AND reserve_price > 0 AND current_bid < reserve_price AND sold = 'n'))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -204,8 +204,9 @@
     $_SESSION['ca_ord'] = 'title';
     $_SESSION['ca_type'] = 'asc';
 } elseif (!empty($_GET['ca_ord'])) {
-    $_SESSION['ca_ord'] = $_GET['ca_ord'];
-    $_SESSION['ca_type'] = $_GET['ca_type'];
+	// check oa_ord && oa_type are valid
+    $_SESSION['ca_ord'] = (in_array($_GET['ca_ord'], array('title', 'starts', 'ends', 'num_bids', 'current_bid'))) ? $_GET['ca_ord'] : 'title';
+    $_SESSION['ca_type'] = (in_array($_GET['ca_type'], array('asc', 'desc'))) ? $_GET['ca_type'] : 'asc';
 } elseif (isset($_SESSION['ca_ord']) && empty($_GET['ca_ord'])) {
     $_SESSION['ca_nexttype'] = $_SESSION['ca_type'];
 }
```
