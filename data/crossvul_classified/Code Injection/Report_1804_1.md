# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 1804_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1804_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 3084-3125 of the vulnerable file.


  }elseif ($config->get_cfg_value("core","gosaSupportURI") != ""){

    // Try using gosa-si
  	$res= gosaSupportDaemon::send("gosa_gen_smb_hash", "GOSA", array("password" => $password), TRUE);
    if (isset($res['XML']['HASH'])){
    	$hash= $res['XML']['HASH'];
    } else {
      $hash= "";
    }

    if ($hash == "") {
      msg_dialog::display(_("Configuration error"), _("Cannot generate SAMBA hash!"), ERROR_DIALOG);
      return ("");
    }
  } else {
      $password = addcslashes($password, '$'); // <- Escape $ twice for transport from PHP to console-process.
      $password = addcslashes($password, '$'); 
      $password = addcslashes($password, '$'); // <- And again once, to be able to use it as parameter for the perl script.
	  $tmp = $config->get_cfg_value("core",'sambaHashHook');
      $tmp = preg_replace("/%userPassword/", escapeshellarg($password), $tmp);
      $tmp = preg_replace("/%password/", escapeshellarg($password), $tmp);
	  @DEBUG (DEBUG_LDAP, __LINE__, __FUNCTION__, __FILE__, $tmp, "Execute");

 	  exec($tmp, $ar);
	  flush();
	  reset($ar);
	  $hash= current($ar);

    if ($hash == "") {
      msg_dialog::display(_("Configuration error"), sprintf(_("Generating SAMBA hash by running %s failed: check %s!"), bold($config->get_cfg_value("core",'sambaHashHook'), bold("sambaHashHook"))), ERROR_DIALOG);
      return(array());
    }
  }

  list($lm,$nt)= explode(":", trim($hash));

  $attrs['sambaLMPassword']= $lm;
  $attrs['sambaNTPassword']= $nt;
  $attrs['sambaPwdLastSet']= date('U');
  $attrs['sambaBadPasswordCount']= "0";
  $attrs['sambaBadPasswordTime']= "0";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3101,8 +3101,8 @@
       $password = addcslashes($password, '$'); 
       $password = addcslashes($password, '$'); // <- And again once, to be able to use it as parameter for the perl script.
 	  $tmp = $config->get_cfg_value("core",'sambaHashHook');
-      $tmp = preg_replace("/%userPassword/", escapeshellarg($password), $tmp);
-      $tmp = preg_replace("/%password/", escapeshellarg($password), $tmp);
+      $tmp = preg_replace("/%userPassword/", base64_encode($password), $tmp);
+      $tmp = preg_replace("/%password/", base64_encode($password), $tmp);
 	  @DEBUG (DEBUG_LDAP, __LINE__, __FUNCTION__, __FILE__, $tmp, "Execute");
 
  	  exec($tmp, $ar);
```
