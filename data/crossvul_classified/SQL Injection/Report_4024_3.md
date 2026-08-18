# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4024_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4024_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 17-59 of the vulnerable file.

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
require_once("../functions/PragRepFnc.php");
$text = "
--
-- Dumping data for table `app`
--



INSERT INTO `app` (`name`, `value`) VALUES
('version', '7.3'),
('date', 'August 23, 2019'),
('build', '20190823001'),
('update', '0'),
('last_updated', 'August 23, 2019');

--
-- Dumping data for table `address`
--


--
-- Dumping data for table `attendance_calendar`
--


--
-- Dumping data for table `school_calendars`
--


--
-- Dumping data for table `attendance_codes`
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,11 +34,11 @@
 
 
 INSERT INTO `app` (`name`, `value`) VALUES
-('version', '7.3'),
-('date', 'August 23, 2019'),
-('build', '20190823001'),
+('version', '7.4'),
+('date', 'April 25, 2020'),
+('build', '20200425001'),
 ('update', '0'),
-('last_updated', 'August 23, 2019');
+('last_updated', 'April 25, 2020');
 
 --
 -- Dumping data for table `address`
```
