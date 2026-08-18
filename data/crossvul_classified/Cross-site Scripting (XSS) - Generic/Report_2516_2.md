# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2516_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2516_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 14-55 of the vulnerable file.


 Website Baker is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Website Baker; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 -----------------------------------------------------------------------------------------
  DEUTSCHE SPRACHDATEI FUER DAS MODUL: USER_SEARCH
 -----------------------------------------------------------------------------------------
*/

// Deutsche Modulbeschreibung
$module_description = 'Dieses Modul bietet eine Suchfunktion f&uuml;r die Benutzerverwaltung.';

// Textausgaben
$MOD_USER_SEARCH['HEADING']				= 'Benutzer Suche';
$MOD_USER_SEARCH['HOWTO']				= 'Hier sind einige zus&auml;tzliche Funktionen f&uuml;r die Suche.<br />Sie k&ouml;nnen verschiedene Kriterien kombinieren um die Suche zu verbessern. Falls sie ein Kriterium nicht ben&ouml;tigen, lassen Sie es einfach frei.';
$MOD_USER_SEARCH['SUBMIT_ALERT']		= 'Eine Suche ohne Suchbegriff macht keinen Sinn ;-)';
$MOD_USER_SEARCH['SUBMIT_TERM_ALERT'] 	= 'Wenn Sie einen Suchberiff angeben, m&uuml;ssen Sie mindestens ein Suchfeld ausw&auml;hlen!';
$MOD_USER_SEARCH['SEARCH_ITEM']			= 'Suchbegriff';
$MOD_USER_SEARCH['USE_WILDCARD']		= 'Verwenden Sie * als Wildcard.';
$MOD_USER_SEARCH['SEARCH_HELP']			= '<i><b>B&uuml;ch*</b></i> findet "B&uuml;chner", aber auch "B&uuml;cher".<br /><i><b>*ner</b></i> findet "B&uuml;chner", aber auch "Wagner".<br /><i><b>*&uuml;ch*</b></i> findet "B&uuml;chner", aber auch "B&uuml;cher" ebenso wie "n&uuml;chtern".<hr size="1" style="margin: 5px 0;" />Groß-/Kleinschreibung wird nicht ber&uuml;cksichtigt.';
$MOD_USER_SEARCH['SEARCH_IN']			= 'Suchen in';
$MOD_USER_SEARCH['USER_NAME']			= 'Benutzer Name';
$MOD_USER_SEARCH['EDIT_USER']			= 'Klicken Sie um den Anwender zu bearbeiten';
$MOD_USER_SEARCH['REAL_NAME']			= 'Angezeigter Name';
$MOD_USER_SEARCH['EMAIL']				= 'Email Adresse';
$MOD_USER_SEARCH['LAST_IP']				= 'IP Adresse';
$MOD_USER_SEARCH['REF_DATE']			= 'Bezugsdatum';
$MOD_USER_SEARCH['REF_DATE_LAST_LOGIN'] = 'Wann zuletzt eingeloggt';
$MOD_USER_SEARCH['USE_CALENDAR']		= 'Nutzen Sie den Kalender um ein Datum einzugeben';
$MOD_USER_SEARCH['REF_DATE_AFTER']		= 'Nach diesem Datum';
$MOD_USER_SEARCH['REF_DATE_BEFORE']		= 'Vor diesem Datum';
$MOD_USER_SEARCH['SEARCH_GROUPS']		= 'Suche alle Benutzer in dieser Gruppe';
$MOD_USER_SEARCH['IN_ALL_GROUPS']		= 'Alle Gruppen';
$MOD_USER_SEARCH['BUTTON_SEARCH']		= 'suchen';
$MOD_USER_SEARCH['HEADING_RESULT']		= 'Ergebnisse der Suche';
$MOD_USER_SEARCH['HOWTO_RESULT']		= 'Ihre Suche wird hier angezeigt.<br />Sie k&ouml;nnen Anwender dirket von dieser Seite aus kontaktieren oder bearbeiten';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,8 +31,8 @@
 
 // Textausgaben
 $MOD_USER_SEARCH['HEADING']				= 'Benutzer Suche';
-$MOD_USER_SEARCH['HOWTO']				= 'Hier sind einige zus&auml;tzliche Funktionen f&uuml;r die Suche.<br />Sie k&ouml;nnen verschiedene Kriterien kombinieren um die Suche zu verbessern. Falls sie ein Kriterium nicht ben&ouml;tigen, lassen Sie es einfach frei.';
-$MOD_USER_SEARCH['SUBMIT_ALERT']		= 'Eine Suche ohne Suchbegriff macht keinen Sinn ;-)';
+$MOD_USER_SEARCH['HOWTO']				= 'Hier sind einige zus&auml;tzliche Funktionen f&uuml;r die Suche. <br />Sie k&ouml;nnen verschiedene Kriterien kombinieren um die Suche zu verbessern. Falls sie ein Kriterium nicht ben&ouml;tigen, lassen Sie es einfach frei.';
+$MOD_USER_SEARCH['SUBMIT_ALERT']		= 'Eine Suche ohne Suchbegriff ergibt keinen Sinn ;-)';
 $MOD_USER_SEARCH['SUBMIT_TERM_ALERT'] 	= 'Wenn Sie einen Suchberiff angeben, m&uuml;ssen Sie mindestens ein Suchfeld ausw&auml;hlen!';
 $MOD_USER_SEARCH['SEARCH_ITEM']			= 'Suchbegriff';
 $MOD_USER_SEARCH['USE_WILDCARD']		= 'Verwenden Sie * als Wildcard.';
```
