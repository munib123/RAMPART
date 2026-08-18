# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 796_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `796_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 530-570 of the vulnerable file.

		include_spip('inc/headers');
		redirige_url_ecrire("install");
	} else {
		// Si on est dans le site public, dire que qq s'en occupe
		include_spip('inc/minipres');
		utiliser_langue_visiteur();
		echo minipres(_T('info_travaux_titre'), "<p style='text-align: center;'>" . _T('info_travaux_texte') . "</p>");
		exit;
	}
	// autrement c'est une install ad hoc (spikini...), on sait pas faire
}

// memoriser un tri sessionne eventuel
if (isset($_REQUEST['var_memotri'])
	and $t = $_REQUEST['var_memotri']
	and (strncmp($t, 'trisession', 10) == 0 or strncmp($t, 'senssession', 11) == 0)
) {
	if (!function_exists('session_set')) {
		include_spip('inc/session');
	}
	session_set($t, _request($t));
}

/**
 * Header "Composed-By"
 *
 * Vanter notre art de la composition typographique
 * La globale $spip_header_silencieux permet de rendre le header minimal pour raisons de securite
 */
if (!defined('_HEADER_COMPOSED_BY')) {
	define('_HEADER_COMPOSED_BY', "Composed-By: SPIP");
}
if (!headers_sent() and _HEADER_COMPOSED_BY) {
	header("Vary: Cookie, Accept-Encoding");
	if (!isset($GLOBALS['spip_header_silencieux']) or !$GLOBALS['spip_header_silencieux']) {
		include_spip('inc/filtres_mini');
		header(_HEADER_COMPOSED_BY . " $spip_version_affichee @ www.spip.net + " . url_absolue(_DIR_VAR . "config.txt"));
	} else {
		// header minimal
		header(_HEADER_COMPOSED_BY . " @ www.spip.net");
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -547,7 +547,10 @@
 	if (!function_exists('session_set')) {
 		include_spip('inc/session');
 	}
-	session_set($t, _request($t));
+	$t = preg_replace(",\W,","_", $t);
+	if ($v = _request($t)) {
+		session_set($t, $v);
+	}
 }
 
 /**
```
