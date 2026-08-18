# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2791_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2791_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 50-90 of the vulnerable file.

if ($action == 'classin' && $user->rights->don->creer)
{
	$object->fetch($id);
	$object->setProject($projectid);
}

/*
 * View
 */
$title = $langs->trans('Donation') . " - " . $langs->trans('Info');
$helpurl = "";
llxHeader('', $title, $helpurl);

$form = new Form($db);
if (! empty($conf->projet->enabled)) { $formproject = new FormProjets($db); }

$object->info($id);

$head = donation_prepare_head($object);

dol_fiche_head($head, 'info', $langs->trans("Donation"), 0, 'generic');

$linkback = '<a href="'.DOL_URL_ROOT.'/don/list.php'.(! empty($socid)?'?socid='.$socid:'').'">'.$langs->trans("BackToList").'</a>';

$morehtmlref='<div class="refidno">';
// Project
if (! empty($conf->projet->enabled))
{
    $langs->load("projects");
    $morehtmlref.=$langs->trans('Project') . ' ';
    if ($user->rights->don->creer)
    {
        if ($action != 'classify')
            // $morehtmlref.='<a href="' . $_SERVER['PHP_SELF'] . '?action=classify&amp;id=' . $object->id . '">' . img_edit($langs->transnoentitiesnoconv('SetProject')) . '</a> : ';
            if ($action == 'classify') {
                //$morehtmlref.=$form->form_project($_SERVER['PHP_SELF'] . '?id=' . $object->id, $object->socid, $object->fk_project, 'projectid', 0, 0, 1, 1);
                $morehtmlref.='<form method="post" action="'.$_SERVER['PHP_SELF'].'?id='.$object->id.'">';
                $morehtmlref.='<input type="hidden" name="action" value="classin">';
                $morehtmlref.='<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
                $morehtmlref.=$formproject->select_projects($object->socid, $object->fk_project, 'projectid', $maxlength, 0, 1, 0, 1, 0, 0, '', 1);
                $morehtmlref.='<input type="submit" class="button valignmiddle" value="'.$langs->trans("Modify").'">';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,7 +67,7 @@
 
 $head = donation_prepare_head($object);
 
-dol_fiche_head($head, 'info', $langs->trans("Donation"), 0, 'generic');
+dol_fiche_head($head, 'info', $langs->trans("Donation"), -1, 'generic');
 
 $linkback = '<a href="'.DOL_URL_ROOT.'/don/list.php'.(! empty($socid)?'?socid='.$socid:'').'">'.$langs->trans("BackToList").'</a>';
 
@@ -116,7 +116,7 @@
 print '<table width="100%"><tr><td>';
 dol_print_object_info($object);
 print '</td></tr></table>';
-      
+
 print '</div>';
 
 dol_fiche_end();
```
