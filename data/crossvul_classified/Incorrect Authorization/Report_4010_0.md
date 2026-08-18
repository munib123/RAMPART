# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4010_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4010_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 168-208 of the vulnerable file.

          scrollTop: target.offset().top
        }, 300);

    })
});
</script>
';


if (empty($user->socid))	// If internal user or not defined
{
	$conf->standard_menu = (empty($conf->global->MAIN_MENU_STANDARD_FORCED) ? (empty($conf->global->MAIN_MENU_STANDARD) ? 'eldy_menu.php' : $conf->global->MAIN_MENU_STANDARD) : $conf->global->MAIN_MENU_STANDARD_FORCED);
}
else                        	// If external user
{
	$conf->standard_menu = (empty($conf->global->MAIN_MENUFRONT_STANDARD_FORCED) ? (empty($conf->global->MAIN_MENUFRONT_STANDARD) ? 'eldy_menu.php' : $conf->global->MAIN_MENUFRONT_STANDARD) : $conf->global->MAIN_MENUFRONT_STANDARD_FORCED);
}

// Load the menu manager (only if not already done)
$file_menu = $conf->standard_menu;
if (GETPOST('menu')) $file_menu = GETPOST('menu'); // example: menu=eldy_menu.php
if (!class_exists('MenuManager'))
{
	$menufound = 0;
	$dirmenus = array_merge(array("/core/menus/"), (array) $conf->modules_parts['menus']);
	foreach ($dirmenus as $dirmenu)
	{
		$menufound = dol_include_once($dirmenu."standard/".$file_menu);
		if ($menufound) break;
	}
	if (!$menufound)	// If failed to include, we try with standard
	{
		dol_syslog("You define a menu manager '".$file_menu."' that can not be loaded.", LOG_WARNING);
		$file_menu = 'eldy_menu.php';
		include_once DOL_DOCUMENT_ROOT."/core/menus/standard/".$file_menu;
	}
}
$menumanager = new MenuManager($db, empty($user->socid) ? 0 : 1);
$menumanager->loadMenu('all', 'all'); // Load this->tabMenu with sql menu entries
//var_dump($menumanager);exit;
$menumanager->showmenu('jmobile');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -185,7 +185,7 @@
 
 // Load the menu manager (only if not already done)
 $file_menu = $conf->standard_menu;
-if (GETPOST('menu')) $file_menu = GETPOST('menu'); // example: menu=eldy_menu.php
+if (GETPOST('menu', 'aZ09')) $file_menu = GETPOST('menu', 'aZ09');     // example: menu=eldy_menu.php
 if (!class_exists('MenuManager'))
 {
 	$menufound = 0;
```
