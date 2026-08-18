# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 684_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `684_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 413-470 of the vulnerable file.

//var_dump($elementList);


$sql="SELECT rowid as rowid, label, type_template, lang, fk_user, private, position, topic, joinfiles, content_lines, content, active";
$sql.=" FROM ".MAIN_DB_PREFIX."c_email_templates";
$sql.=" WHERE entity IN (".getEntity('email_template').")";
if (! $user->admin)
{
	$sql.=" AND (private = 0 OR (private = 1 AND fk_user = ".$user->id."))";	// Show only public and private to me
	$sql.=" AND (active = 1 OR fk_user = ".$user->id.")";						// Show only active or owned by me
}
if (empty($conf->global->MAIN_MULTILANGS))
{
	$sql.= " AND (lang = '".$langs->defaultlang."' OR lang IS NULL OR lang = '')";
}
if ($search_label) $sql.=natural_search('label', $search_label);
if ($search_type_template != '' && $search_type_template != '-1') $sql.=natural_search('type_template', $search_type_template);
if ($search_lang) $sql.=natural_search('lang', $search_lang);
if ($search_fk_user != '' && $search_fk_user != '-1') $sql.=natural_search('fk_user', $search_fk_user, 2);
if ($search_topic) $sql.=natural_search('topic', $search_topic);
if ($sortfield)
{
    // If sort order is "country", we use country_code instead
	if ($sortfield == 'country') $sortfield='country_code';
    $sql.= " ORDER BY ".$sortfield;
    if ($sortorder)
    {
        $sql.=" ".strtoupper($sortorder);
    }
    $sql.=", ";
    // Clear the required sort criteria for the tabsqlsort to be able to force it with selected value
    $tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.' '.$sortorder.',/i','',$tabsqlsort[$id]);
    $tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.',/i','',$tabsqlsort[$id]);
}
else {
    $sql.=" ORDER BY ";
}
$sql.=$tabsqlsort[$id];
$sql.=$db->plimit($listlimit+1,$offset);
//print $sql;

$fieldlist=explode(',',$tabfield[$id]);

// Form to add a new line
$alabelisused=0;
$var=false;

print '<form action="'.$_SERVER['PHP_SELF'].'?id='.$id.'" method="POST">';
print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
print '<input type="hidden" name="from" value="'.dol_escape_htmltag(GETPOST('from','alpha')).'">';

print '<div class="div-table-responsive-no-min">';
print '<table class="noborder" width="100%">';

// Line to enter new values (title)
print '<tr class="liste_titre">';
foreach ($fieldlist as $field => $value)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -430,24 +430,9 @@
 if ($search_lang) $sql.=natural_search('lang', $search_lang);
 if ($search_fk_user != '' && $search_fk_user != '-1') $sql.=natural_search('fk_user', $search_fk_user, 2);
 if ($search_topic) $sql.=natural_search('topic', $search_topic);
-if ($sortfield)
-{
-    // If sort order is "country", we use country_code instead
-	if ($sortfield == 'country') $sortfield='country_code';
-    $sql.= " ORDER BY ".$sortfield;
-    if ($sortorder)
-    {
-        $sql.=" ".strtoupper($sortorder);
-    }
-    $sql.=", ";
-    // Clear the required sort criteria for the tabsqlsort to be able to force it with selected value
-    $tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.' '.$sortorder.',/i','',$tabsqlsort[$id]);
-    $tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.',/i','',$tabsqlsort[$id]);
-}
-else {
-    $sql.=" ORDER BY ";
-}
-$sql.=$tabsqlsort[$id];
+// If sort order is "country", we use country_code instead
+if ($sortfield == 'country') $sortfield='country_code';
+$sql.=$db->order($sortfield,$sortorder);
 $sql.=$db->plimit($listlimit+1,$offset);
 //print $sql;
 
```
