# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_17
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_17`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 92-133 of the vulnerable file.

$query = "SELECT count(id) AS COUNT FROM " . $DBPrefix . "auctions WHERE user = :user_id and starts > CURRENT_TIMESTAMP AND suspended = 0";
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
if (!isset($_SESSION['pa_ord']) && empty($_GET['pa_ord'])) {
    $_SESSION['pa_ord'] = 'title';
    $_SESSION['pa_type'] = 'asc';
} elseif (!empty($_GET['pa_ord'])) {
    $_SESSION['pa_ord'] = $_GET['pa_ord'];
    $_SESSION['pa_type'] = $_GET['pa_type'];
} elseif (isset($_SESSION['pa_ord']) && empty($_GET['pa_ord'])) {
    $_SESSION['pa_nexttype'] = $_SESSION['pa_type'];
}

if (!isset($_SESSION['pa_nexttype']) || $_SESSION['pa_nexttype'] == 'desc') {
    $_SESSION['pa_nexttype'] = 'asc';
} else {
    $_SESSION['pa_nexttype'] = 'desc';
}

if (!isset($_SESSION['pa_type']) || $_SESSION['pa_type'] == 'desc') {
    $_SESSION['pa_type_img'] = '<img src="images/arrow_up.gif" align="center" hspace="2" border="0" />';
} else {
    $_SESSION['pa_type_img'] = '<img src="images/arrow_down.gif" align="center" hspace="2" border="0" />';
}
$query = "SELECT * FROM " . $DBPrefix . "auctions au
	WHERE user = :user_id AND starts > CURRENT_TIMESTAMP AND suspended = 0
	ORDER BY " . $_SESSION['pa_ord'] . " " . $_SESSION['pa_type'] . " LIMIT :offset, :perpage";
$params = array();
$params[] = array(':user_id', $user->user_data['id'], 'int');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,8 +109,9 @@
     $_SESSION['pa_ord'] = 'title';
     $_SESSION['pa_type'] = 'asc';
 } elseif (!empty($_GET['pa_ord'])) {
-    $_SESSION['pa_ord'] = $_GET['pa_ord'];
-    $_SESSION['pa_type'] = $_GET['pa_type'];
+	// check oa_ord && oa_type are valid
+    $_SESSION['pa_ord'] = (in_array($_GET['pa_ord'], array('title', 'starts', 'ends'))) ? $_GET['pa_ord'] : 'title';
+    $_SESSION['pa_type'] = (in_array($_GET['pa_type'], array('asc', 'desc'))) ? $_GET['pa_type'] : 'asc';
 } elseif (isset($_SESSION['pa_ord']) && empty($_GET['pa_ord'])) {
     $_SESSION['pa_nexttype'] = $_SESSION['pa_type'];
 }
```
