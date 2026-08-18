# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2318_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2318_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 6-46 of the vulnerable file.

it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CookieViz is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with CookieViz.  If not, see <http://www.gnu.org/licenses/>.*/


require "connect.php";
require "load_point.php";
$domain="";
$init_max_date=0;

if(isset($_GET["max_date"]))
{
	$init_max_date = $_GET["max_date"];
}

if(isset($_GET["domain"]))
{
	$domain = $_GET["domain"];
}

$max_date = $init_max_date;
$point_map = new point_map($domain);
$map = $point_map->get_map();
$write_nodes='[';
$write_links='[';
$cpt_unique_nodes=0;
$cpt_unique_links=0;
$color = "#00f0ff";
$min_date=0;
$cpt=0;
if (isset($map))
{
	if (strcmp($domain, "") == 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,12 +23,16 @@
 
 if(isset($_GET["max_date"]))
 {
-	$init_max_date = $_GET["max_date"];
+	$init_max_date = 	mysql_real_escape_string($_GET["max_date"]);
+	if (!is_numeric($init_max_date))
+	{
+		$init_max_date="";
+	}
 }
 
 if(isset($_GET["domain"]))
 {
-	$domain = $_GET["domain"];
+	$domain = mysql_real_escape_string($_GET["domain"]);
 }
 
 $max_date = $init_max_date;
```
