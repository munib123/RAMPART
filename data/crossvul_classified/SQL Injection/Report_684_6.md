# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 684_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `684_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 402-459 of the vulnerable file.

print load_fiche_titre($titre,$linkback,'title_setup');

print $langs->trans("WebsiteSetupDesc").'<br>';
print "<br>\n";


// Confirmation de la suppression de la ligne
if ($action == 'delete')
{
    print $form->formconfirm($_SERVER["PHP_SELF"].'?'.($page?'page='.$page.'&':'').'sortfield='.$sortfield.'&sortorder='.$sortorder.'&rowid='.$rowid, $langs->trans('DeleteWebsite'), $langs->trans('ConfirmDeleteWebsite'), 'confirm_delete','',0,1);
}
//var_dump($elementList);

/*
 * Show website list
 */
if ($id)
{
    // Complete requete recherche valeurs avec critere de tri
    $sql=$tabsql[$id];

    if ($sortfield)
    {
        // If sort order is "country", we use country_code instead
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
    $sql.=$db->plimit($limit+1, $offset);
    //print $sql;

    $fieldlist=explode(',',$tabfield[$id]);

    print '<form action="'.$_SERVER['PHP_SELF'].'" method="POST">';
    print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
    print '<table class="noborder" width="100%">';

    // Form to add a new line
    if ($tabname[$id])
    {
        $alabelisused=0;
        $var=false;

        $fieldlist=explode(',',$tabfield[$id]);

        // Line for title
        print '<tr class="liste_titre">';
        foreach ($fieldlist as $field => $value)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -419,24 +419,7 @@
 {
     // Complete requete recherche valeurs avec critere de tri
     $sql=$tabsql[$id];
-
-    if ($sortfield)
-    {
-        // If sort order is "country", we use country_code instead
-        $sql.= " ORDER BY ".$sortfield;
-        if ($sortorder)
-        {
-            $sql.=" ".strtoupper($sortorder);
-        }
-        $sql.=", ";
-        // Clear the required sort criteria for the tabsqlsort to be able to force it with selected value
-        $tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.' '.$sortorder.',/i','',$tabsqlsort[$id]);
-        $tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.',/i','',$tabsqlsort[$id]);
-    }
-    else {
-        $sql.=" ORDER BY ";
-    }
-    $sql.=$tabsqlsort[$id];
+    $sql.=$db->order($sortfield,$sortorder);
     $sql.=$db->plimit($limit+1, $offset);
     //print $sql;
 
```
