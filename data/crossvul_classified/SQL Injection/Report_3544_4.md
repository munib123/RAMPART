# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3544_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3544_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 18-58 of the vulnerable file.

 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *       \file       htdocs/user/fiche.php
 *       \brief      Tab of user card
 *       \version    $Id: fiche.php,v 1.275 2011/07/31 23:19:43 eldy Exp $
 */

require("../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/user/class/user.class.php");
require_once(DOL_DOCUMENT_ROOT."/user/class/usergroup.class.php");
require_once(DOL_DOCUMENT_ROOT."/contact/class/contact.class.php");
require_once(DOL_DOCUMENT_ROOT."/lib/images.lib.php");
require_once(DOL_DOCUMENT_ROOT."/lib/usergroups.lib.php");
if ($conf->ldap->enabled) require_once(DOL_DOCUMENT_ROOT."/lib/ldap.class.php");
if ($conf->adherent->enabled) require_once(DOL_DOCUMENT_ROOT."/adherents/class/adherent.class.php");

// Define value to know what current user can do on users
$canadduser=($user->admin || $user->rights->user->user->creer);
$canreaduser=($user->admin || $user->rights->user->user->lire);
$canedituser=($user->admin || $user->rights->user->user->creer);
$candisableuser=($user->admin || $user->rights->user->user->supprimer);
$canreadgroup=$canreaduser;
$caneditgroup=$canedituser;
if (! empty($conf->global->MAIN_USE_ADVANCED_PERMS))
{
    $canreadgroup=($user->admin || $user->rights->user->group_advance->read);
    $caneditgroup=($user->admin || $user->rights->user->group_advance->write);
}
// Define value to know what current user can do on properties of edited user
if ($_GET["id"])
{
    // $user est le user qui edite, $_GET["id"] est l'id de l'utilisateur edite
    $caneditfield=( (($user->id == $_GET["id"]) && $user->rights->user->self->creer)
    || (($user->id != $_GET["id"]) && $user->rights->user->user->creer) );
    $caneditpassword=( (($user->id == $_GET["id"]) && $user->rights->user->self->password)
    || (($user->id != $_GET["id"]) && $user->rights->user->user->password) );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,6 +35,11 @@
 if ($conf->ldap->enabled) require_once(DOL_DOCUMENT_ROOT."/lib/ldap.class.php");
 if ($conf->adherent->enabled) require_once(DOL_DOCUMENT_ROOT."/adherents/class/adherent.class.php");
 
+$id=GETPOST('id','int');
+$action=GETPOST("action");
+$group=GETPOST("group","int",3);
+$confirm=GETPOST("confirm");
+
 // Define value to know what current user can do on users
 $canadduser=($user->admin || $user->rights->user->user->creer);
 $canreaduser=($user->admin || $user->rights->user->user->lire);
@@ -48,26 +53,22 @@
     $caneditgroup=($user->admin || $user->rights->user->group_advance->write);
 }
 // Define value to know what current user can do on properties of edited user
-if ($_GET["id"])
+if ($id)
 {
-    // $user est le user qui edite, $_GET["id"] est l'id de l'utilisateur edite
-    $caneditfield=( (($user->id == $_GET["id"]) && $user->rights->user->self->creer)
-    || (($user->id != $_GET["id"]) && $user->rights->user->user->creer) );
-    $caneditpassword=( (($user->id == $_GET["id"]) && $user->rights->user->self->password)
-    || (($user->id != $_GET["id"]) && $user->rights->user->user->password) );
+    // $user est le user qui edite, $id est l'id de l'utilisateur edite
+    $caneditfield=( (($user->id == $id) && $user->rights->user->self->creer)
+    || (($user->id != $id) && $user->rights->user->user->creer) );
+    $caneditpassword=( (($user->id == $id) && $user->rights->user->self->password)
+    || (($user->id != $id) && $user->rights->user->user->password) );
 }
-
-$action=GETPOST("action");
-$group=GETPOST("group","int",3);
-$confirm=GETPOST("confirm");
 
 // Security check
 $socid=0;
 if ($user->societe_id > 0) $socid = $user->societe_id;
 $feature2='user';
-if ($user->id == $_GET["id"]) { $feature2=''; $canreaduser=1; } // A user can always read its own card
-$result = restrictedArea($user, 'user', $_GET["id"], '', $feature2);
-if ($user->id <> $_GET["id"] && ! $canreaduser) accessforbidden();
+if ($user->id == $id) { $feature2=''; $canreaduser=1; } // A user can always read its own card
+$result = restrictedArea($user, 'user', $id, '', $feature2);
+if ($user->id <> $id && ! $canreaduser) accessforbidden();
 
 $langs->load("users");
 $langs->load("companies");
@@ -82,36 +83,36 @@
 if ($_GET["subaction"] == 'addrights' && $canedituser)
 {
     $edituser = new User($db);
-    $edituser->fetch($_GET["id"]);
+    $edituser->fetch($id);
     $edituser->addrights($_GET["rights"]);
 }
 
 if ($_GET["subaction"] == 'delrights' && $canedituser)
 {
     $edituser = new User($db);
-    $edituser->fetch($_GET["id"]);
+    $edituser->fetch($id);
     $edituser->delrights($_GET["rights"]);
 }
 
 if ($action == 'confirm_disable' && $confirm == "yes" && $candisableuser)
 {
-    if ($_GET["id"] <> $user->id)
+    if ($id <> $user->id)
     {
         $edituser = new User($db);
-        $edituser->fetch($_GET["id"]);
+        $edituser->fetch($id);
         $edituser->setstatus(0);
-        Header("Location: ".DOL_URL_ROOT.'/user/fiche.php?id='.$_GET["id"]);
+        Header("Location: ".DOL_URL_ROOT.'/user/fiche.php?id='.$id);
         exit;
     }
 }
 if ($action == 'confirm_enable' && $confirm == "yes" && $candisableuser)
 {
-    if ($_GET["id"] <> $user->id)
+    if ($id <> $user->id)
     {
         $message='';
 
         $edituser = new User($db);
-        $edituser->fetch($_GET["id"]);
+        $edituser->fetch($id);
 
         if (!empty($conf->file->main_limit_users))
         {
@@ -125,7 +126,7 @@
         if (! $message)
         {
             $edituser->setstatus(1);
-            Header("Location: ".DOL_URL_ROOT.'/user/fiche.php?id='.$_GET["id"]);
+            Header("Location: ".DOL_URL_ROOT.'/user/fiche.php?id='.$id);
             exit;
         }
     }
@@ -133,10 +134,10 @@
 
 if ($action == 'confirm_delete' && $confirm == "yes" && $candisableuser)
 {
-    if ($_GET["id"] <> $user->id)
+    if ($id <> $user->id)
     {
         $edituser = new User($db);
-        $edituser->id=$_GET["id"];
+        $edituser->id=$id;
         $result = $edituser->delete();
         if ($result < 0)
         {
@@ -232,13 +233,13 @@
         $editgroup->oldcopy=dol_clone($editgroup);
 
         $edituser = new User($db);
-        $edituser->fetch($_GET["id"]);
+        $edituser->fetch($id);
         if ($action == 'addgroup')    $edituser->SetInGroup($group,GETPOST('entity'));
         if ($action == 'removegroup') $edituser->RemoveFromGroup($group,GETPOST('entity'));
 
         if ($result > 0)
         {
-            header("Location: fiche.php?id=".$_GET["id"]);
+            header("Location: fiche.php?id=".$id);
             exit;
         }
         else
@@ -271,7 +272,7 @@
         {
             $db->begin();
             $edituser = new User($db);
-            $edituser->fetch($_GET["id"]);
+            $edituser->fetch($id);
 
             $edituser->oldcopy=dol_clone($edituser);
 
@@ -360,7 +361,7 @@
     else if ($caneditpassword)	// Case we can edit only password
     {
         $edituser = new User($db);
-        $edituser->fetch($_GET["id"]);
+        $edituser->fetch($id);
 
         $edituser->oldcopy=dol_clone($edituser);
 
@@ -377,7 +378,7 @@
 || ($action == 'confirm_passwordsend' && $confirm == 'yes')) && $caneditpassword)
 {
     $edituser = new User($db);
-    $edituser->fetch($_GET["id"]);
+    $edituser->fetch($id);
 
     $newpassword=$edituser->setPassword($user,'');
     if ($newpassword < 0)
@@ -800,10 +801,10 @@
     /*                                                                            */
     /* ************************************************************************** */
 
-    if ($_GET["id"])
+    if ($id)
     {
         $fuser = new User($db);
-        $fuser->fetch($_GET["id"]);
+        $fuser->fetch($id);
 
         // Connexion ldap
         // pour recuperer passDoNotExpire et userChangePassNextLogon
@@ -1169,13 +1170,13 @@
             // Si on a un gestionnaire de generation de mot de passe actif
             if ($conf->global->USER_PASSWORD_GENERATED != 'none')
             {
-                if (($user->id != $_GET["id"] && $caneditpassword) && $fuser->login && !$fuser->ldap_sid &&
+                if (($user->id != $id && $caneditpassword) && $fuser->login && !$fuser->ldap_sid &&
                 (empty($conf->multicompany->enabled) || ($fuser->entity == $conf->entity)))
                 {
                     print '<a class="butAction" href="fiche.php?id='.$fuser->id.'&amp;action=password">'.$langs->trans("ReinitPassword").'</a>';
                 }
 
-                if (($user->id != $_GET["id"] && $caneditpassword) && $fuser->login && !$fuser->ldap_sid &&
+                if (($user->id != $id && $caneditpassword) && $fuser->login && !$fuser->ldap_sid &&
                 (empty($conf->multicompany->enabled) || ($fuser->entity == $conf->entity)) )
                 {
                     if ($fuser->email) print '<a class="butAction" href="fiche.php?id='.$fuser->id.'&amp;action=passwordsend">'.$langs->trans("SendNewPassword").'</a>';
@@ -1184,19 +1185,19 @@
             }
 
             // Activer
-            if ($user->id <> $_GET["id"] && $candisableuser && $fuser->statut == 0 &&
+            if ($user->id <> $id && $candisableuser && $fuser->statut == 0 &&
             (empty($conf->multicompany->enabled) || ($fuser->entity == $conf->entity)) )
             {
                 print '<a class="butAction" href="fiche.php?id='.$fuser->id.'&amp;action=enable">'.$langs->trans("Reactivate").'</a>';
             }
             // Desactiver
-            if ($user->id <> $_GET["id"] && $candisableuser && $fuser->statut == 1 &&
+            if ($user->id <> $id && $candisableuser && $fuser->statut == 1 &&
             (empty($conf->multicompany->enabled) || ($fuser->entity == $conf->entity)) )
             {
                 print '<a class="butActionDelete" href="fiche.php?action=disable&amp;id='.$fuser->id.'">'.$langs->trans("DisableUser").'</a>';
... (diff truncated)
```
