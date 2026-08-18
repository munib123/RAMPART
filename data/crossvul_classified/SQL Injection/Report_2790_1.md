# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2790_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2790_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 66-106 of the vulnerable file.

if ($action == 'update')
{
    if (! $_POST['cancel'])
    {
        $leftmenu=''; $mainmenu='';
        if (! empty($_POST['menuIdParent']) && ! is_numeric($_POST['menuIdParent']))
        {
            $tmp=explode('&',$_POST['menuIdParent']);
            foreach($tmp as $s)
            {
                if (preg_match('/fk_mainmenu=/',$s))
                {
                    $mainmenu=preg_replace('/fk_mainmenu=/','',$s);
                }
                if (preg_match('/fk_leftmenu=/',$s))
                {
                    $leftmenu=preg_replace('/fk_leftmenu=/','',$s);
                }
            }
        }
        
        $menu = new Menubase($db);
        $result=$menu->fetch($_POST['menuId']);
        if ($result > 0)
        {
            $menu->titre=$_POST['titre'];
            $menu->leftmenu=$_POST['leftmenu'];
            $menu->url=$_POST['url'];
            $menu->langs=$_POST['langs'];
            $menu->position=$_POST['position'];
            $menu->enabled=$_POST['enabled'];
            $menu->perms=$_POST['perms'];
            $menu->target=$_POST['target'];
            $menu->user=$_POST['user'];
            if (is_numeric($_POST['menuIdParent']))
            {
            	$menu->fk_menu=$_POST['menuIdParent'];
            }
            else
            {
    	       	if ($_POST['type'] == 'top') $menu->fk_menu=0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,27 +83,27 @@
                 }
             }
         }
-        
+
         $menu = new Menubase($db);
-        $result=$menu->fetch($_POST['menuId']);
+        $result=$menu->fetch(GETPOST('menuId', 'int'));
         if ($result > 0)
         {
-            $menu->titre=$_POST['titre'];
-            $menu->leftmenu=$_POST['leftmenu'];
-            $menu->url=$_POST['url'];
-            $menu->langs=$_POST['langs'];
-            $menu->position=$_POST['position'];
-            $menu->enabled=$_POST['enabled'];
-            $menu->perms=$_POST['perms'];
-            $menu->target=$_POST['target'];
-            $menu->user=$_POST['user'];
-            if (is_numeric($_POST['menuIdParent']))
+            $menu->titre=GETPOST('titre', 'alpha');
+            $menu->leftmenu=GETPOST('leftmenu', 'alpha');
+            $menu->url=GETPOST('url','alpha');
+            $menu->langs=GETPOST('langs','alpha');
+            $menu->position=GETPOST('position','int');
+            $menu->enabled=GETPOST('enabled','alpha');
+            $menu->perms=GETPOST('perms','alpha');
+            $menu->target=GETPOST('target','alpha');
+            $menu->user=GETPOST('user','alpha');
+            if (is_numeric(GETPOST('menuIdParent','alpha')))
             {
-            	$menu->fk_menu=$_POST['menuIdParent'];
+            	$menu->fk_menu=GETPOST('menuIdParent','alpha');
             }
             else
             {
-    	       	if ($_POST['type'] == 'top') $menu->fk_menu=0;
+    	       	if (GETPOST('type','alpha') == 'top') $menu->fk_menu=0;
     	       	else $menu->fk_menu=-1;
             	$menu->fk_mainmenu=$mainmenu;
             	$menu->fk_leftmenu=$leftmenu;
@@ -123,7 +123,6 @@
         {
 	        setEventMessages($menu->error, $menu->errors, 'errors');
         }
-        $_GET["menuId"] = $_POST['menuId'];
         $action = "edit";
     }
     else
@@ -148,9 +147,9 @@
     }
 
     $leftmenu=''; $mainmenu='';
-    if (! empty($_POST['menuId']) && ! is_numeric($_POST['menuId']))
-    {
-	    $tmp=explode('&',$_POST['menuId']);
+    if (GETPOST('menuId','int') && ! is_numeric(GETPOST('menuId','int')))
+    {
+	    $tmp=explode('&',GETPOST('menuId','int'));
 	    foreach($tmp as $s)
 	    {
 	    	if (preg_match('/fk_mainmenu=/',$s))
@@ -197,7 +196,7 @@
         $action = 'create';
         $error++;
     }
-    if (! $error && empty($_POST['menuId']) && $_POST['type'] == 'left')
+    if (! $error && ! $_POST['menuId'] && $_POST['type'] == 'left')
     {
 	    setEventMessages($langs->trans("ErrorLeftMenuMustHaveAParentId"), null, 'errors');
         $action = 'create';
@@ -207,23 +206,23 @@
     if (! $error)
     {
         $menu = new Menubase($db);
-        $menu->menu_handler=preg_replace('/_menu$/','',$_POST['menu_handler']);
-        $menu->type=$_POST['type'];
-        $menu->titre=$_POST['titre'];
-        $menu->url=$_POST['url'];
-        $menu->langs=$_POST['langs'];
-        $menu->position=$_POST['position'];
-        $menu->enabled=$_POST['enabled'];
-        $menu->perms=$_POST['perms'];
-        $menu->target=$_POST['target'];
-        $menu->user=$_POST['user'];
-        if (is_numeric($_POST['menuId']))
-        {
-        	$menu->fk_menu=$_POST['menuId'];
+        $menu->menu_handler=preg_replace('/_menu$/','',GETPOST('menu_handler','aZ09'));
+        $menu->type=GETPOST('type','alpha');
+        $menu->titre=GETPOST('titre','alpha');
+        $menu->url=GETPOST('url','alpha');
+        $menu->langs=GETPOST('langs','alpha');
+        $menu->position=GETPOST('position','int');
+        $menu->enabled=GETPOST('enabled','alpha');
+        $menu->perms=GETPOST('perms','alpha');
+        $menu->target=GETPOST('target','alpha');
+        $menu->user=GETPOST('user','alpha');
+        if (is_numeric(GETPOST('menuId','int')))
+        {
+        	$menu->fk_menu=GETPOST('menuId','int');
         }
         else
        {
-	       	if ($_POST['type'] == 'top') $menu->fk_menu=0;
+	       	if (GETPOST('type','alpha') == 'top') $menu->fk_menu=0;
 	       	else $menu->fk_menu=-1;
         	$menu->fk_mainmenu=$mainmenu;
         	$menu->fk_leftmenu=$leftmenu;
@@ -232,7 +231,7 @@
         $result=$menu->create($user);
         if ($result > 0)
         {
-            header("Location: ".DOL_URL_ROOT."/admin/menus/index.php?menu_handler=".$_POST['menu_handler']);
+            header("Location: ".DOL_URL_ROOT."/admin/menus/index.php?menu_handler=".GETPOST('menu_handler','aZ09'));
             exit;
         }
         else
@@ -305,17 +304,17 @@
     </script>';
 
     print load_fiche_titre($langs->trans("NewMenu"),'','title_setup');
-    
-    print '<form action="./edit.php?action=add&menuId='.$_GET['menuId'].'" method="post" name="formmenucreate">';
+
+    print '<form action="./edit.php?action=add&menuId='.GETPOST('menuId', 'int').'" method="post" name="formmenucreate">';
     print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
 
     dol_fiche_head();
-    
+
     print '<table class="border" width="100%">';
 
     // Id
-    $parent_rowid = $_GET['menuId'];
-    if ($_GET['menuId'])
+    $parent_rowid = GETPOST('menuId', 'int');
+    if (GETPOST('menuId', 'int'))
     {
         $sql = "SELECT m.rowid, m.mainmenu, m.leftmenu, m.level, m.langs FROM ".MAIN_DB_PREFIX."menu as m WHERE m.rowid = ".GETPOST('menuId', 'int');
         $res  = $db->query($sql);
@@ -375,40 +374,40 @@
     }
     else
     {
-        print '<td><input type="text" size="48" id="menuId" name="menuId" value="'.($_POST["menuId"]?$_POST["menuId"]:'').'"></td>';
+        print '<td><input type="text" size="48" id="menuId" name="menuId" value="'.(GETPOST("menuId", 'int')?GETPOST("menuId", 'int'):'').'"></td>';
     }
     print '<td>'.$langs->trans('DetailMenuIdParent');
     print ', '.$langs->trans("Example").': fk_mainmenu=abc&fk_leftmenu=def';
     print '</td></tr>';
 
     // Title
-    print '<tr><td class="fieldrequired">'.$langs->trans('Title').'</td><td><input type="text" size="30" name="titre" value="'.$_POST["titre"].'"></td><td>'.$langs->trans('DetailTitre').'</td></tr>';
+    print '<tr><td class="fieldrequired">'.$langs->trans('Title').'</td><td><input type="text" size="30" name="titre" value="'.dol_escape_htmltag(GETPOST("titre",'alpha')).'"></td><td>'.$langs->trans('DetailTitre').'</td></tr>';
 
     // URL
-    print '<tr><td class="fieldrequired">'.$langs->trans('URL').'</td><td><input type="text" size="60" name="url" value="'.$_POST["url"].'"></td><td>'.$langs->trans('DetailUrl').'</td></tr>';
+    print '<tr><td class="fieldrequired">'.$langs->trans('URL').'</td><td><input type="text" size="60" name="url" value="'.GETPOST("url",'alpha').'"></td><td>'.$langs->trans('DetailUrl').'</td></tr>';
 
     // Langs
     print '<tr><td>'.$langs->trans('LangFile').'</td><td><input type="text" size="30" name="langs" value="'.$parent_langs.'"></td><td>'.$langs->trans('DetailLangs').'</td></tr>';
 
     // Position
-    print '<tr><td>'.$langs->trans('Position').'</td><td><input type="text" size="5" name="position" value="'.(isset($_POST["position"])?$_POST["position"]:100).'"></td><td>'.$langs->trans('DetailPosition').'</td></tr>';
+    print '<tr><td>'.$langs->trans('Position').'</td><td><input type="text" size="5" name="position" value="'.dol_escape_htmltag(isset($_POST["position"])?$_POST["position"]:100).'"></td><td>'.$langs->trans('DetailPosition').'</td></tr>';
 
     // Target
     print '<tr><td>'.$langs->trans('Target').'</td><td><select class="flat" name="target">';
-    print '<option value=""'.($menu->target==""?' selected':'').'>'.$langs->trans('').'</option>';
+    print '<option value=""'.($menu->target==""?' selected':'').'>&nbsp;</option>';
     print '<option value="_blank"'.($menu->target=="_blank"?' selected':'').'>'.$langs->trans('_blank').'</option>';
     print '</select></td></td><td>'.$langs->trans('DetailTarget').'</td></tr>';
 
     // Enabled
... (diff truncated)
```
