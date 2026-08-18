# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_19
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_19`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 132-173 of the vulnerable file.

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
if (!isset($_SESSION['solda_ord']) && empty($_GET['solda_ord'])) {
    $_SESSION['solda_ord'] = 'title';
    $_SESSION['solda_type'] = 'asc';
} elseif (!empty($_GET['solda_ord'])) {
    $_SESSION['solda_ord'] = $_GET['solda_ord'];
    $_SESSION['solda_type'] = $_GET['solda_type'];
} elseif (isset($_SESSION['solda_ord']) && empty($_GET['solda_ord'])) {
    $_SESSION['solda_nexttype'] = $_SESSION['solda_type'];
}

if (!isset($_SESSION['solda_nexttype']) || $_SESSION['solda_nexttype'] == 'desc') {
    $_SESSION['solda_nexttype'] = 'asc';
} else {
    $_SESSION['solda_nexttype'] = 'desc';
}

if (!isset($_SESSION['solda_type']) || $_SESSION['solda_type'] == 'desc') {
    $_SESSION['solda_type_img'] = '<img src="images/arrow_up.gif" align="center" hspace="2" border="0" alt="up"/>';
} else {
    $_SESSION['solda_type_img'] = '<img src="images/arrow_down.gif" align="center" hspace="2" border="0" alt="down"/>';
}

$query = "SELECT a.* FROM " . $DBPrefix . "auctions a
	LEFT JOIN " . $DBPrefix . "winners w ON (a.id = w.auction)
	WHERE a.user = :user_id
	AND a.closed = 1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -149,8 +149,9 @@
     $_SESSION['solda_ord'] = 'title';
     $_SESSION['solda_type'] = 'asc';
 } elseif (!empty($_GET['solda_ord'])) {
-    $_SESSION['solda_ord'] = $_GET['solda_ord'];
-    $_SESSION['solda_type'] = $_GET['solda_type'];
+	// check oa_ord && oa_type are valid
+    $_SESSION['solda_ord'] = (in_array($_GET['solda_ord'], array('title', 'starts', 'ends', 'num_bids', 'current_bid'))) ? $_GET['solda_ord'] : 'title';
+    $_SESSION['solda_type'] = (in_array($_GET['solda_type'], array('asc', 'desc'))) ? $_GET['solda_type'] : 'asc';
 } elseif (isset($_SESSION['solda_ord']) && empty($_GET['solda_ord'])) {
     $_SESSION['solda_nexttype'] = $_SESSION['solda_type'];
 }
```
