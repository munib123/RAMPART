# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_18
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_18`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 64-105 of the vulnerable file.

// Retrieve active auctions from the database
$query = "SELECT count(id) as COUNT FROM " . $DBPrefix . "auctions WHERE user = :user_id AND suspended != 0";
$params = array();
$params[] = array(':user_id', $user->user_data['id'], 'int');
$db->query($query, $params);
$TOTALAUCTIONS = $db->result('COUNT');

if (!isset($_GET['PAGE']) || $_GET['PAGE'] < 0 || empty($_GET['PAGE'])) {
    $OFFSET = 0;
    $PAGE = 1;
} else {
    $PAGE = intval($_GET['PAGE']);
    $OFFSET = ($PAGE - 1) * $system->SETTINGS['perpage'];
}
$PAGES = ($TOTALAUCTIONS == 0) ? 1 : ceil($TOTALAUCTIONS / $system->SETTINGS['perpage']);
// Handle columns sorting variables
if (!isset($_SESSION['sa_ord']) && empty($_GET['sa_ord'])) {
    $_SESSION['sa_ord'] = 'title';
    $_SESSION['sa_type'] = 'asc';
} elseif (!empty($_GET['sa_ord'])) {
    $_SESSION['sa_ord'] = $_GET['sa_ord'];
    $_SESSION['sa_type'] = $_GET['sa_type'];
} elseif (isset($_SESSION['sa_ord']) && empty($_GET['sa_ord'])) {
    $_SESSION['sa_nexttype'] = $_SESSION['sa_type'];
}

if (!isset($_SESSION['sa_nexttype']) || $_SESSION['sa_nexttype'] == 'desc') {
    $_SESSION['sa_nexttype'] = 'asc';
} else {
    $_SESSION['sa_nexttype'] = 'desc';
}

if (!isset($_SESSION['sa_type']) || $_SESSION['sa_type'] == 'desc') {
    $_SESSION['sa_type_img'] = '<img src="images/arrow_up.gif" align="center" hspace="2" border="0" />';
} else {
    $_SESSION['sa_type_img'] = '<img src="images/arrow_down.gif" align="center" hspace="2" border="0" />';
}
$query = "SELECT id, title, current_bid, num_bids, relist, relisted, current_bid, suspended
	FROM " . $DBPrefix . "auctions
	WHERE user = :user_id
	AND suspended != 0
	ORDER BY " . $_SESSION['sa_ord'] . " " . $_SESSION['sa_type'] . " LIMIT :offset, :perpage";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,8 +81,9 @@
     $_SESSION['sa_ord'] = 'title';
     $_SESSION['sa_type'] = 'asc';
 } elseif (!empty($_GET['sa_ord'])) {
-    $_SESSION['sa_ord'] = $_GET['sa_ord'];
-    $_SESSION['sa_type'] = $_GET['sa_type'];
+	// check oa_ord && oa_type are valid
+    $_SESSION['sa_ord'] = (in_array($_GET['sa_ord'], array('title', 'num_bids', 'current_bid'))) ? $_GET['sa_ord'] : 'title';
+    $_SESSION['sa_type'] = (in_array($_GET['sa_type'], array('asc', 'desc'))) ? $_GET['sa_type'] : 'asc';
 } elseif (isset($_SESSION['sa_ord']) && empty($_GET['sa_ord'])) {
     $_SESSION['sa_nexttype'] = $_SESSION['sa_type'];
 }
```
