# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 79_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `79_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 12-53 of the vulnerable file.

 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *	\file 		htdocs/adherents/cartes/carte.php
 *	\ingroup    member
 *	\brief      Page to output members business cards
 */
require '../../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/format_cards.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/files.lib.php';
require_once DOL_DOCUMENT_ROOT.'/adherents/class/adherent.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/modules/member/modules_cards.php';
require_once DOL_DOCUMENT_ROOT.'/core/modules/printsheet/modules_labels.php';

$langs->load("members");
$langs->load("errors");

// Choix de l'annee d'impression ou annee courante.
$now = dol_now();
$year=dol_print_date($now,'%Y');
$month=dol_print_date($now,'%m');
$day=dol_print_date($now,'%d');
$foruserid=GETPOST('foruserid');
$foruserlogin=GETPOST('foruserlogin');
$mode=GETPOST('mode');
$model=GETPOST("model");			// Doc template to use for business cards
$modellabel=GETPOST("modellabel");	// Doc template to use for address sheet
$mesg='';

$adherentstatic=new Adherent($db);

$extrafields = new ExtraFields($db);
// fetch optionals attributes and labels
$extralabels = $extrafields->fetch_name_optionals_label('adherent');


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,19 +29,18 @@
 require_once DOL_DOCUMENT_ROOT.'/core/modules/member/modules_cards.php';
 require_once DOL_DOCUMENT_ROOT.'/core/modules/printsheet/modules_labels.php';
 
-$langs->load("members");
-$langs->load("errors");
+$langs->loadLangs(array("members","errors"));
 
 // Choix de l'annee d'impression ou annee courante.
 $now = dol_now();
 $year=dol_print_date($now,'%Y');
 $month=dol_print_date($now,'%m');
 $day=dol_print_date($now,'%d');
-$foruserid=GETPOST('foruserid');
-$foruserlogin=GETPOST('foruserlogin');
-$mode=GETPOST('mode');
-$model=GETPOST("model");			// Doc template to use for business cards
-$modellabel=GETPOST("modellabel");	// Doc template to use for address sheet
+$foruserid=GETPOST('foruserid','alphanohtml');
+$foruserlogin=GETPOST('foruserlogin','alphanohtml');
+$mode=GETPOST('mode','aZ09');
+$model=GETPOST("model",'aZ09');				// Doc template to use for business cards
+$modellabel=GETPOST("modellabel",'aZ09');	// Doc template to use for address sheet
 $mesg='';
 
 $adherentstatic=new Adherent($db);
```
