# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in php
**Pair ID:** 185_0
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `185_0`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```php
Lines 8-50 of the vulnerable file.

(at your option) any later version.

Ice Framework is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ice Framework. If not, see <http://www.gnu.org/licenses/>.

------------------------------------------------------------------

Original work Copyright (c) 2012 [Gamonoid Media Pvt. Ltd]
Developer: Thilina Hasantha (thilina.hasantha[at]gmail.com / facebook.com/thilinah)
 */
if (!defined('MODULE_NAME')) {
    define('MODULE_NAME', $moduleName);
}
include 'includes.inc.php';

if(empty($user)){
    $actualLink = "http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
    header("Location:".CLIENT_BASE_URL."login.php?next=".\Base64Url\Base64Url::encode($actualLink));
    exit();
}

if(empty($user->default_module)){
    if($user->user_level == "Admin"){
        $homeLink = HOME_LINK_ADMIN;
    }else{
        $homeLink = HOME_LINK_OTHERS;
    }
}else{
    $defaultModule = new \Modules\Common\Model\Module();
    $defaultModule->Load("id = ?",array($user->default_module));
    if($defaultModule->mod_group == "user"){
        $defaultModule->mod_group = "modules";
    }
    $homeLink = CLIENT_BASE_URL."?g=".$defaultModule->mod_group."&n=".$defaultModule->name.
        "&m=".$defaultModule->mod_group."_".str_replace(" ","_",$defaultModule->menu);
}


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,9 +25,9 @@
 }
 include 'includes.inc.php';
 
-if(empty($user)){
-    $actualLink = "http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
-    header("Location:".CLIENT_BASE_URL."login.php?next=".\Base64Url\Base64Url::encode($actualLink));
+if(empty($user) || empty($user->email)){
+    $actualLinkArray = explode('/',$_SERVER['REQUEST_URI']);
+    header("Location:".CLIENT_BASE_URL."login.php?next=".\Base64Url\Base64Url::encode($actualLinkArray[count($actualLinkArray) - 1]));
     exit();
 }
 
```
