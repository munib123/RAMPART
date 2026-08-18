# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 4068_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4068_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 15-47 of the vulnerable file.

 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OCSInventory-NG/OCSInventory-ocsreports. if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

/**
 *  CommandLine class
 */
class CommandLine
{
    public function get_mib_oid($file) {
        $oids = [];

        $champs = array('SNMP_MIB_DIRECTORY' => 'SNMP_MIB_DIRECTORY');
        $values = look_config_default_values($champs);
        $cmd = "snmptranslate -Tz -m ".$values['tvalue']['SNMP_MIB_DIRECTORY']."/".$file;
        $result_cmd = shell_exec($cmd);
        $result_cmd = preg_split("/\r\n|\n|\r/", $result_cmd);
        $result_cmd = str_replace('"', "", $result_cmd);

        foreach ($result_cmd as $label => $oid) {
            $split = preg_split('/\t/', $oid, null, PREG_SPLIT_NO_EMPTY);
            if($split[0] != "") {
                $oids[$split[0]] = $split[1]; 
            } 
        }
        return $oids;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
         $champs = array('SNMP_MIB_DIRECTORY' => 'SNMP_MIB_DIRECTORY');
         $values = look_config_default_values($champs);
         $cmd = "snmptranslate -Tz -m ".$values['tvalue']['SNMP_MIB_DIRECTORY']."/".$file;
-        $result_cmd = shell_exec($cmd);
+        $result_cmd = shell_exec(escapeshellcmd($cmd));
         $result_cmd = preg_split("/\r\n|\n|\r/", $result_cmd);
         $result_cmd = str_replace('"', "", $result_cmd);
 
```
