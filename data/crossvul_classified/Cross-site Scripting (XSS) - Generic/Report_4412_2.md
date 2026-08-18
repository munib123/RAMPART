# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4412_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4412_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 13-36 of the vulnerable file.

#  an email to info@os4ed.com.
#
#  This program is released under the terms of the GNU General Public License as  
#  published by the Free Software Foundation, version 2 of the License. 
#  See license.txt.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#***************************************************************************************
session_start();
unset($_SESSION['student_id']);
unset($_SESSION['students_order']);
unset($_SESSION['_REQUEST_vars']);
unset($_SESSION['_REQUEST_vars']);
echo "<script>window.location.href='Modules.php?modname=".strip_tags(trim($_REQUEST['modname']))."&ajax=true';</script>";


?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,7 @@
 unset($_SESSION['students_order']);
 unset($_SESSION['_REQUEST_vars']);
 unset($_SESSION['_REQUEST_vars']);
-echo "<script>window.location.href='Modules.php?modname=".strip_tags(trim($_REQUEST['modname']))."&ajax=true';</script>";
+echo "<script>window.location.href='Modules.php?modname=".strip_tags(urlencode(trim($_REQUEST['modname'])))."&ajax=true';</script>";
 
 
 ?>
```
