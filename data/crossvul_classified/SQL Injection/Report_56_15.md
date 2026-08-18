# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_15
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_15`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 82-123 of the vulnerable file.

$query = "SELECT count(id) AS COUNT FROM " . $DBPrefix . "auctions WHERE user = :user_id AND closed = 0 AND starts <= CURRENT_TIMESTAMP AND suspended = 0";
$params = array();
$params[] = array(':user_id', $user->user_data['id'], 'int');
$db->query($query, $params);
$TOTALAUCTIONS = $db->result('COUNT');

if (!isset($_GET['PAGE']) || $_GET['PAGE'] <= 1 || $_GET['PAGE'] == '') {
    $OFFSET = 0;
    $PAGE = 1;
} else {
    $PAGE = intval($_GET['PAGE']);
    $OFFSET = ($PAGE - 1) * $system->SETTINGS['perpage'];
}
$PAGES = ($TOTALAUCTIONS == 0) ? 1 : ceil($TOTALAUCTIONS / $system->SETTINGS['perpage']);

// Handle columns sorting variables
if (!isset($_SESSION['oa_ord']) && empty($_GET['oa_ord'])) {
    $_SESSION['oa_ord'] = 'title';
    $_SESSION['oa_type'] = 'asc';
} elseif (!empty($_GET['oa_ord'])) {
    $_SESSION['oa_ord'] = $_GET['oa_ord'];
    $_SESSION['oa_type'] = $_GET['oa_type'];
} elseif (isset($_SESSION['oa_ord']) && empty($_GET['oa_ord'])) {
    $_SESSION['oa_nexttype'] = $_SESSION['oa_type'];
}
if (!isset($_SESSION['oa_nexttype']) || $_SESSION['oa_nexttype'] == 'desc') {
    $_SESSION['oa_nexttype'] = 'asc';
} else {
    $_SESSION['oa_nexttype'] = 'desc';
}
if (!isset($_SESSION['oa_type']) || $_SESSION['oa_type'] == 'desc') {
    $_SESSION['oa_type_img'] = '<img src="images/arrow_up.gif" align="center" hspace="2" border="0" />';
} else {
    $_SESSION['oa_type_img'] = '<img src="images/arrow_down.gif" align="center" hspace="2" border="0" />';
}

$query = "SELECT * FROM " . $DBPrefix . "auctions
	WHERE user = :user_id AND closed = 0
	AND starts <= CURRENT_TIMESTAMP AND suspended = 0
	ORDER BY " . $_SESSION['oa_ord'] . " " . $_SESSION['oa_type'] . " LIMIT :offset, :perpage";
$params = array();
$params[] = array(':user_id', $user->user_data['id'], 'int');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,8 +99,9 @@
     $_SESSION['oa_ord'] = 'title';
     $_SESSION['oa_type'] = 'asc';
 } elseif (!empty($_GET['oa_ord'])) {
-    $_SESSION['oa_ord'] = $_GET['oa_ord'];
-    $_SESSION['oa_type'] = $_GET['oa_type'];
+	// check oa_ord && oa_type are valid
+    $_SESSION['oa_ord'] = (in_array($_GET['oa_ord'], array('title', 'starts', 'ends', 'num_bids', 'current_bid'))) ? $_GET['oa_ord'] : 'title';
+    $_SESSION['oa_type'] = (in_array($_GET['oa_type'], array('asc', 'desc'))) ? $_GET['oa_type'] : 'asc';
 } elseif (isset($_SESSION['oa_ord']) && empty($_GET['oa_ord'])) {
     $_SESSION['oa_nexttype'] = $_SESSION['oa_type'];
 }
```
